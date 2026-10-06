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
	Owner       string           `json:"owner,omitempty"`
	Status      string           `json:"status"`
	ExpiresUnix int64            `json:"expires_unix"`
	Detail      string           `json:"detail,omitempty"`
}
type Store interface {
	Put(context.Context, compose.Prepared, string) error
	Claim(context.Context, string, string, string, time.Time) (Record, bool, error)
	Complete(context.Context, string, string, string) error
	Status(context.Context, string, string, time.Time) (SendStatus, error)
}

// SendStatus is a receipt projection, never a prepared message or approval.
// ExpiresAt is the original preparation deadline, not the receipt's retention.
type SendStatus struct {
	Status    string     `json:"status"`
	MessageID string     `json:"message_id,omitempty"`
	Stage     string     `json:"stage,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
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
	return r.commandLimited(ctx, 24<<20, args...)
}

func (r *Redis) commandLimited(ctx context.Context, limit int64, args ...any) (json.RawMessage, error) {
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
	raw, e := io.ReadAll(io.LimitReader(res.Body, limit))
	if e != nil || int64(len(raw)) >= limit {
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
func validOwner(owner string) bool {
	if len(owner) != 64 {
		return false
	}
	for _, c := range owner {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func (r *Redis) Put(ctx context.Context, p compose.Prepared, owner string) error {
	k, e := key(p.ID)
	if e != nil {
		return e
	}
	if !validOwner(owner) {
		return errors.New("verified preparation owner required")
	}
	v, e := json.Marshal(Record{Message: p, Owner: owner, Status: "prepared", ExpiresUnix: p.ExpiresAt.Unix()})
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

// Legacy unowned records retain their exact-ID/digest send contract until their
// existing TTL expires. All newly prepared records are owner-bound; ownership
// is checked before returning a consumed record or the full claimed payload.
const claimScript = `local v=redis.call('GET',KEYS[1]); if not v then return {'missing',''} end; local r=cjson.decode(v); if r.owner ~= nil and r.owner ~= '' and r.owner ~= ARGV[3] then return {'missing',''} end; if r.message.digest ~= ARGV[1] then return {'mismatch',''} end; if r.status ~= 'prepared' then return {'existing',v} end; if r.expires_unix <= tonumber(ARGV[2]) then return {'expired',''} end; r.status='sending'; r.message={id=r.message.id,digest=r.message.digest,message_id=r.message.message_id,expires_at=r.message.expires_at}; redis.call('SET',KEYS[1],cjson.encode(r),'EX',604800); return {'claimed',v}`

func (r *Redis) Claim(ctx context.Context, id, digest, owner string, now time.Time) (Record, bool, error) {
	var rec Record
	k, e := key(id)
	if e != nil {
		return rec, false, e
	}
	if len(digest) != 64 {
		return rec, false, errors.New("invalid approval digest")
	}
	if owner != "" && !validOwner(owner) {
		return rec, false, errors.New("invalid preparation owner")
	}
	v, e := r.command(ctx, "EVAL", claimScript, 1, k, digest, strconv.FormatInt(now.Unix(), 10), owner)
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
	if rec.Owner != "" && rec.Owner != owner {
		return Record{}, false, errors.New("prepared message missing, expired, or digest mismatch")
	}
	return rec, parts[0] == "claimed", nil
}

// Only GET is executed: no claim, payload projection, deletion or TTL refresh.
// Unknown, foreign and legacy-unowned IDs deliberately have the same response.
const statusScript = `local v=redis.call('GET',KEYS[1]); if not v then return {'unavailable','','',''} end
local r=cjson.decode(v); if not r.owner or r.owner == '' or r.owner ~= ARGV[1] then return {'unavailable','','',''} end
local status=r.status; if status == 'prepared' and r.expires_unix <= tonumber(ARGV[2]) then status='expired' end
local stage=''; local allowed={validation=true,integrity_validation=true,connection=true,authentication=true,envelope=true,data=true,acknowledgement=true}; if type(r.detail)=='string' and allowed[r.detail] then stage=r.detail end
return {status,r.message.message_id or '',tostring(r.expires_unix),stage}`

func (r *Redis) Status(ctx context.Context, id, owner string, now time.Time) (SendStatus, error) {
	k, e := key(id)
	if e != nil {
		return SendStatus{}, e
	}
	if !validOwner(owner) {
		return SendStatus{Status: "unavailable"}, nil
	}
	v, e := r.commandLimited(ctx, 8<<10, "EVAL", statusScript, 1, k, owner, strconv.FormatInt(now.Unix(), 10))
	if e != nil {
		return SendStatus{}, e
	}
	var parts []string
	if json.Unmarshal(v, &parts) != nil || len(parts) != 4 {
		return SendStatus{}, errors.New("invalid send status response")
	}
	if parts[0] == "unavailable" {
		return SendStatus{Status: "unavailable"}, nil
	}
	switch parts[0] {
	case "prepared", "sending", "accepted", "rejected", "unknown", "expired":
	default:
		return SendStatus{}, errors.New("invalid send status response")
	}
	expires, e := strconv.ParseInt(parts[2], 10, 64)
	if e != nil || expires <= 0 {
		return SendStatus{}, errors.New("invalid send status expiry")
	}
	deadline := time.Unix(expires, 0).UTC()
	if deadline.Year() > 9999 {
		return SendStatus{}, errors.New("invalid send status expiry")
	}
	messageID := parts[1]
	if messageID != "" {
		var valid bool
		if len(messageID) > 997 {
			return SendStatus{}, errors.New("invalid send status Message-ID")
		}
		messageID, valid = compose.NormalizeMessageID(messageID)
		if !valid {
			return SendStatus{}, errors.New("invalid send status Message-ID")
		}
	}
	stage := parts[3]
	switch stage {
	case "validation", "integrity_validation", "connection", "authentication", "envelope", "data", "acknowledgement":
	default:
		stage = ""
	}
	return SendStatus{Status: parts[0], MessageID: messageID, ExpiresAt: &deadline, Stage: stage}, nil
}

const completeScript = `local v=redis.call('GET',KEYS[1]); if not v then return 0 end; local r=cjson.decode(v); if r.status ~= 'sending' then return 0 end; r.status=ARGV[1]; r.detail=ARGV[2]; r.message.raw=nil; r.message.text=nil; r.message.html=nil; r.message.recipients=nil; r.message.to=nil; r.message.cc=nil; r.message.bcc=nil; r.message.attachments=nil; redis.call('SET',KEYS[1],cjson.encode(r),'EX',604800); return 1`

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
