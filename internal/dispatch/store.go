// Package dispatch stores immutable prepared messages and consumes each send ID once.
// SMTP cannot guarantee exactly-once delivery: a lost final response is "unknown".
package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/amxv/angelos/internal/compose"
)

type Record struct {
	Message     compose.Prepared `json:"message"`
	Status      string           `json:"status"`
	ExpiresUnix int64            `json:"expires_unix"`
	Detail      string           `json:"detail,omitempty"`
}
type Store interface {
	Put(context.Context, compose.Prepared) error
	Claim(context.Context, string, string, time.Time) (Record, bool, error)
	Complete(context.Context, string, string, string) error
}
type Redis struct {
	endpoint, token string
	client          *http.Client
}

func NewRedis(endpoint, token string) (*Redis, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(token) < 8 {
		return nil, errors.New("invalid Redis REST configuration")
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		if len(ips) == 0 {
			return nil, errors.New("no Redis addresses")
		}
		for _, ip := range ips {
			if !public(ip) {
				return nil, errors.New("nonpublic Redis destination denied")
			}
		}
		var last error
		for _, ip := range ips {
			c, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return c, nil
			}
			last = e
		}
		return nil, last
	}}
	return &Redis{endpoint: strings.TrimRight(endpoint, "/"), token: token, client: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Redis redirects denied") }}}, nil
}
func public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func (r *Redis) command(ctx context.Context, args ...any) (json.RawMessage, error) {
	b, e := json.Marshal(args)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	res, e := r.client.Do(req)
	if e != nil {
		return nil, errors.New("durable send store unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("durable send store rejected operation")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 24<<20))
	if e != nil || len(raw) >= 24<<20 {
		return nil, errors.New("invalid durable store response")
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Error != "" {
		return nil, errors.New("durable send store command failed")
	}
	return out.Result, nil
}
func key(id string) (string, error) {
	if len(id) != 32 {
		return "", errors.New("invalid prepared id")
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", errors.New("invalid prepared id")
		}
	}
	return "angelos:send:" + id, nil
}
func (r *Redis) Put(ctx context.Context, p compose.Prepared) error {
	k, e := key(p.ID)
	if e != nil {
		return e
	}
	v, e := json.Marshal(Record{Message: p, Status: "prepared", ExpiresUnix: p.ExpiresAt.Unix()})
	if e != nil {
		return e
	}
	result, e := r.command(ctx, "SET", k, string(v), "NX", "EX", 900)
	if e != nil {
		return e
	}
	var s string
	if json.Unmarshal(result, &s) != nil || s != "OK" {
		return errors.New("preparation already exists")
	}
	return nil
}

const claimScript = `local v=redis.call('GET',KEYS[1]); if not v then return {'missing',''} end; local r=cjson.decode(v); if r.message.digest ~= ARGV[1] then return {'mismatch',''} end; if r.status ~= 'prepared' then return {'existing',v} end; if r.expires_unix <= tonumber(ARGV[2]) then return {'expired',''} end; r.status='sending'; r.message={id=r.message.id,digest=r.message.digest,message_id=r.message.message_id,expires_at=r.message.expires_at}; redis.call('SET',KEYS[1],cjson.encode(r),'EX',604800); return {'claimed',v}`

func (r *Redis) Claim(ctx context.Context, id, digest string, now time.Time) (Record, bool, error) {
	var rec Record
	k, e := key(id)
	if e != nil {
		return rec, false, e
	}
	if len(digest) != 64 {
		return rec, false, errors.New("invalid approval digest")
	}
	v, e := r.command(ctx, "EVAL", claimScript, 1, k, digest, strconv.FormatInt(now.Unix(), 10))
	if e != nil {
		return rec, false, e
	}
	var parts []string
	if json.Unmarshal(v, &parts) != nil || len(parts) != 2 {
		return rec, false, errors.New("invalid claim response")
	}
	if parts[0] != "claimed" && parts[0] != "existing" {
		return rec, false, errors.New("prepared message missing, expired, or digest mismatch")
	}
	if json.Unmarshal([]byte(parts[1]), &rec) != nil {
		return rec, false, errors.New("invalid prepared record")
	}
	return rec, parts[0] == "claimed", nil
}

const completeScript = `local v=redis.call('GET',KEYS[1]); if not v then return 0 end; local r=cjson.decode(v); if r.status ~= 'sending' then return 0 end; r.status=ARGV[1]; r.detail=ARGV[2]; r.message.raw=nil; r.message.text=nil; r.message.recipients=nil; r.message.to=nil; r.message.cc=nil; r.message.bcc=nil; r.message.attachments=nil; redis.call('SET',KEYS[1],cjson.encode(r),'EX',604800); return 1`

func (r *Redis) Complete(ctx context.Context, id, status, detail string) error {
	k, e := key(id)
	if e != nil {
		return e
	}
	if status != "accepted" && status != "rejected" && status != "unknown" {
		return errors.New("invalid completion status")
	}
	v, e := r.command(ctx, "EVAL", completeScript, 1, k, status, detail)
	if e != nil {
		return e
	}
	if string(v) != "1" {
		return errors.New("send status could not be recorded; do not retry")
	}
	return nil
}
