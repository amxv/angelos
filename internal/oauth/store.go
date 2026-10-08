package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound    = errors.New("OAuth state missing or expired")
	ErrConflict    = errors.New("OAuth state already exists or changed")
	ErrReplay      = errors.New("refresh token replay; grant revoked")
	ErrUnavailable = errors.New("OAuth state unavailable")
	ErrRateLimited = errors.New("OAuth rate limit reached")
)

// Store persists the state shared by every stateless authorization-server instance.
// Callers must never retry an ambiguous mutating operation with the same secret.
type Store interface {
	Put(context.Context, string, string, []byte, time.Duration) error
	Get(context.Context, string, string) ([]byte, error)
	Consume(context.Context, string, string) ([]byte, error)
	Delete(context.Context, string, string) error
	CompareAndSwap(context.Context, string, string, []byte, []byte, time.Duration) (bool, error)
	LoadOwner(context.Context) ([]byte, error)
	BootstrapOwner(context.Context, []byte) (bool, error)
	CASOwner(context.Context, []byte, []byte) (bool, error)
	Allow(context.Context, string, int, time.Duration) (bool, error)
	CreateGrant(context.Context, Grant) error
	GetGrant(context.Context, string) (Grant, error)
	ListGrants(context.Context) ([]Grant, error)
	RevokeGrant(context.Context, string) error
	CreateRefresh(context.Context, string, Refresh) error
	RotateRefresh(context.Context, string, string, string, string, time.Time) (Refresh, error)
}

type Grant struct {
	ID          string   `json:"id"`
	Subject     string   `json:"subject"`
	ClientID    string   `json:"client_id"`
	ClientName  string   `json:"client_name"`
	Resource    string   `json:"resource"`
	Scopes      []string `json:"scopes"`
	CreatedUnix int64    `json:"created_unix"`
	ExpiresUnix int64    `json:"expires_unix"`
}
type Refresh struct {
	FamilyID    string   `json:"family_id"`
	GrantID     string   `json:"grant_id"`
	Subject     string   `json:"subject"`
	ClientID    string   `json:"client_id"`
	Resource    string   `json:"resource"`
	Scopes      []string `json:"scopes"`
	ExpiresUnix int64    `json:"expires_unix"`
}

// RedisCommander is implemented by dispatch.Redis. It permits a local ephemeral
// Redis REST bridge in tests without weakening the production HTTPS transport.
type RedisCommander interface {
	Command(context.Context, ...any) (json.RawMessage, error)
}
type RedisStore struct {
	redis         RedisCommander
	prefix, owner string
}

const (
	maxStateBytes      = 32 << 10
	maxOwnerBytes      = 128 << 10
	maxStateTTL        = 30 * 24 * time.Hour
	maxGrants          = 128
	maxFamilyRotations = 10000
)

func NewRedisStore(redis RedisCommander, owner string) (*RedisStore, error) {
	if redis == nil || strings.TrimSpace(owner) == "" || len(owner) > 1024 {
		return nil, errors.New("Redis and explicit OAuth owner required")
	}
	return &RedisStore{redis: redis, owner: owner, prefix: "angelos:oauth:{" + stateHash(owner) + "}:v1:"}, nil
}
func stateHash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func validID(v string) bool     { return v != "" && len(v) <= 4096 }
func (s *RedisStore) stateKey(bucket, id string) (string, error) {
	switch bucket {
	case "code", "challenge", "bootstrap", "session", "credential", "consent", "rate":
	default:
		return "", errors.New("invalid OAuth state bucket")
	}
	if !validID(id) {
		return "", errors.New("invalid OAuth state identifier")
	}
	return s.prefix + bucket + ":" + stateHash(id), nil
}
func bucketTTL(bucket string, ttl time.Duration) error {
	max := maxStateTTL
	switch bucket {
	case "code":
		max = 5 * time.Minute
	case "challenge", "bootstrap", "consent":
		max = 10 * time.Minute
	case "rate":
		max = time.Hour
	case "session":
		max = 24 * time.Hour
	case "credential":
		return errors.New("use atomic owner credential operations")
	}
	if ttl < time.Second || ttl > max || ttl%time.Second != 0 {
		return errors.New("invalid OAuth state TTL")
	}
	return nil
}
func validPayload(data []byte, max int) error {
	if len(data) == 0 || len(data) > max || !json.Valid(data) {
		return errors.New("invalid or oversized OAuth state")
	}
	return nil
}
func (s *RedisStore) command(ctx context.Context, args ...any) (json.RawMessage, error) {
	v, e := s.redis.Command(ctx, args...)
	if e != nil || len(v) == 0 || !json.Valid(v) {
		return nil, ErrUnavailable
	}
	return v, nil
}
func decodeString(v json.RawMessage) ([]byte, error) {
	if string(v) == "null" {
		return nil, ErrNotFound
	}
	var out string
	if json.Unmarshal(v, &out) != nil || len(out) > maxOwnerBytes {
		return nil, ErrUnavailable
	}
	return []byte(out), nil
}
func (s *RedisStore) Put(ctx context.Context, bucket, id string, data []byte, ttl time.Duration) error {
	k, e := s.stateKey(bucket, id)
	if e != nil {
		return e
	}
	if e = bucketTTL(bucket, ttl); e != nil {
		return e
	}
	if e = validPayload(data, maxStateBytes); e != nil {
		return e
	}
	v, e := s.command(ctx, "SET", k, string(data), "NX", "EX", int64(ttl/time.Second))
	if e != nil {
		return e
	}
	if string(v) != "\"OK\"" {
		if string(v) == "null" {
			return ErrConflict
		}
		return ErrUnavailable
	}
	return nil
}
func (s *RedisStore) Get(ctx context.Context, bucket, id string) ([]byte, error) {
	k, e := s.stateKey(bucket, id)
	if e != nil {
		return nil, e
	}
	v, e := s.command(ctx, "GET", k)
	if e != nil {
		return nil, e
	}
	return decodeString(v)
}

const consumeStateScript = `local v=redis.call('GET',KEYS[1]); if not v then return false end; redis.call('DEL',KEYS[1]); return v`

func (s *RedisStore) Consume(ctx context.Context, bucket, id string) ([]byte, error) {
	k, e := s.stateKey(bucket, id)
	if e != nil {
		return nil, e
	}
	v, e := s.command(ctx, "EVAL", consumeStateScript, 1, k)
	if e != nil {
		return nil, e
	}
	return decodeString(v)
}
func (s *RedisStore) Delete(ctx context.Context, bucket, id string) error {
	k, e := s.stateKey(bucket, id)
	if e != nil {
		return e
	}
	v, e := s.command(ctx, "DEL", k)
	if e != nil {
		return e
	}
	if string(v) != "0" && string(v) != "1" {
		return ErrUnavailable
	}
	return nil
}

const compareSwapScript = `local v=redis.call('GET',KEYS[1]); if not v or v~=ARGV[1] then return 0 end; redis.call('SET',KEYS[1],ARGV[2],'EX',ARGV[3]); return 1`

func (s *RedisStore) CompareAndSwap(ctx context.Context, bucket, id string, old, next []byte, ttl time.Duration) (bool, error) {
	k, e := s.stateKey(bucket, id)
	if e != nil {
		return false, e
	}
	if e = bucketTTL(bucket, ttl); e != nil {
		return false, e
	}
	if e = validPayload(next, maxStateBytes); e != nil {
		return false, e
	}
	if len(old) > maxStateBytes {
		return false, errors.New("oversized old state")
	}
	return s.boolCommand(ctx, "EVAL", compareSwapScript, 1, k, string(old), string(next), int64(ttl/time.Second))
}
func (s *RedisStore) boolCommand(ctx context.Context, args ...any) (bool, error) {
	v, e := s.command(ctx, args...)
	if e != nil {
		return false, e
	}
	switch string(v) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, ErrUnavailable
	}
}
func (s *RedisStore) LoadOwner(ctx context.Context) ([]byte, error) {
	v, e := s.command(ctx, "GET", s.prefix+"owner")
	if e != nil {
		return nil, e
	}
	return decodeString(v)
}

const bootstrapOwnerScript = `if redis.call('EXISTS',KEYS[1])==1 or redis.call('EXISTS',KEYS[2])==1 then return 0 end; redis.call('SET',KEYS[1],ARGV[1]); redis.call('SET',KEYS[2],'disabled'); return 1`

func (s *RedisStore) BootstrapOwner(ctx context.Context, owner []byte) (bool, error) {
	if e := validPayload(owner, maxOwnerBytes); e != nil {
		return false, e
	}
	return s.boolCommand(ctx, "EVAL", bootstrapOwnerScript, 2, s.prefix+"owner", s.prefix+"bootstrap-disabled", string(owner))
}

const ownerCASScript = `local v=redis.call('GET',KEYS[1]); if not v or v~=ARGV[1] then return 0 end; redis.call('SET',KEYS[1],ARGV[2]); return 1`

func (s *RedisStore) CASOwner(ctx context.Context, old, next []byte) (bool, error) {
	if e := validPayload(next, maxOwnerBytes); e != nil {
		return false, e
	}
	if len(old) > maxOwnerBytes {
		return false, errors.New("oversized old owner")
	}
	return s.boolCommand(ctx, "EVAL", ownerCASScript, 1, s.prefix+"owner", string(old), string(next))
}

// Existing counters must have a valid count and expiry. Corrupt durable state
// fails closed rather than silently resetting a quota or creating a permanent
// lockout counter. Denied attempts do not extend the window.
const rateLimitLua = `local function allow_rate(key,limit,window) local n=redis.call('GET',key); if n then local count=tonumber(n); if not count or count<1 or count%1~=0 or redis.call('TTL',key)<0 then error('invalid rate state') end; if count>=limit then return false end end; local count=redis.call('INCR',key); if count==1 then redis.call('EXPIRE',key,window) end; return true end
`
const rateScript = rateLimitLua + `if allow_rate(KEYS[1],tonumber(ARGV[1]),tonumber(ARGV[2])) then return 1 else return 0 end`

func (s *RedisStore) Allow(ctx context.Context, bucket string, limit int, window time.Duration) (bool, error) {
	k, e := s.stateKey("rate", bucket)
	if e != nil {
		return false, e
	}
	if limit < 1 || limit > 10000 {
		return false, errors.New("invalid rate limit")
	}
	if e = bucketTTL("rate", window); e != nil {
		return false, e
	}
	return s.boolCommand(ctx, "EVAL", rateScript, 1, k, limit, int64(window/time.Second))
}

// Grants are a bounded owner-scoped hash. Expired members are pruned on reads or
// writes; the whole hash also expires within 30 days of its latest insertion.
const createGrantScript = `local all=redis.call('HGETALL',KEYS[1]); local count=0; for i=1,#all,2 do local g=cjson.decode(all[i+1]); if g.expires_unix<=tonumber(ARGV[3]) then redis.call('HDEL',KEYS[1],all[i]) else count=count+1 end end; if redis.call('HEXISTS',KEYS[1],ARGV[1])==1 then return 0 end; if count>=tonumber(ARGV[4]) then return -1 end; redis.call('HSET',KEYS[1],ARGV[1],ARGV[2]); redis.call('EXPIRE',KEYS[1],ARGV[5]); return 1`

func (s *RedisStore) validateGrant(g Grant, now time.Time) error {
	if !validID(g.ID) || g.Subject != s.owner || !validID(g.ClientID) || len(g.ClientName) > 1024 || !validID(g.Resource) || g.CreatedUnix <= 0 || g.CreatedUnix > now.Unix()+60 || g.ExpiresUnix <= now.Unix() || g.ExpiresUnix > now.Add(maxStateTTL).Unix() || !validStateScopes(g.Scopes) {
		return errors.New("invalid OAuth grant")
	}
	return nil
}
func validStateScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range scopes {
		if seen[v] || (v != "mail.read" && v != "mail.write" && v != "mail.send") {
			return false
		}
		seen[v] = true
	}
	return true
}
func (s *RedisStore) CreateGrant(ctx context.Context, g Grant) error {
	now := time.Now()
	if e := s.validateGrant(g, now); e != nil {
		return e
	}
	raw, _ := json.Marshal(g)
	if len(raw) > 2048 {
		return errors.New("oversized OAuth grant")
	}
	v, e := s.command(ctx, "EVAL", createGrantScript, 1, s.prefix+"grants", stateHash(g.ID), string(raw), now.Unix(), maxGrants, int64(maxStateTTL/time.Second))
	if e != nil {
		return e
	}
	switch string(v) {
	case "1":
		return nil
	case "0", "-1":
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

const getGrantScript = `local v=redis.call('HGET',KEYS[1],ARGV[1]); if not v then return false end; local g=cjson.decode(v); if g.expires_unix<=tonumber(ARGV[2]) then redis.call('HDEL',KEYS[1],ARGV[1]); return false end; return v`

func (s *RedisStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	if !validID(id) {
		return Grant{}, ErrNotFound
	}
	v, e := s.command(ctx, "EVAL", getGrantScript, 1, s.prefix+"grants", stateHash(id), time.Now().Unix())
	if e != nil {
		return Grant{}, e
	}
	raw, e := decodeString(v)
	if e != nil {
		return Grant{}, e
	}
	var g Grant
	if json.Unmarshal(raw, &g) != nil || g.ID != id {
		return Grant{}, ErrUnavailable
	}
	// A grant can expire between the script's snapshot and this response.
	// Deny it as ordinary expiry, never as a backend outage or a valid grant.
	now := time.Now()
	if g.ExpiresUnix <= now.Unix() {
		return Grant{}, ErrNotFound
	}
	if s.validateGrant(g, now) != nil {
		return Grant{}, ErrUnavailable
	}
	return g, nil
}

const listGrantsScript = `local all=redis.call('HGETALL',KEYS[1]); local out={}; for i=1,#all,2 do local g=cjson.decode(all[i+1]); if g.expires_unix<=tonumber(ARGV[1]) then redis.call('HDEL',KEYS[1],all[i]) else table.insert(out,all[i+1]) end end; return out`

func (s *RedisStore) ListGrants(ctx context.Context) ([]Grant, error) {
	v, e := s.command(ctx, "EVAL", listGrantsScript, 1, s.prefix+"grants", time.Now().Unix())
	if e != nil {
		return nil, e
	}
	var all []string
	if json.Unmarshal(v, &all) != nil || len(all) > maxGrants {
		return nil, ErrUnavailable
	}
	out := make([]Grant, 0, len(all))
	now := time.Now()
	for _, raw := range all {
		var g Grant
		if json.Unmarshal([]byte(raw), &g) != nil {
			return nil, ErrUnavailable
		}
		// Exclude grants which expired while the bounded REST read was in flight.
		if g.ExpiresUnix <= now.Unix() {
			continue
		}
		if s.validateGrant(g, now) != nil {
			return nil, ErrUnavailable
		}
		out = append(out, g)
	}
	return out, nil
}
func (s *RedisStore) RevokeGrant(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrNotFound
	}
	v, e := s.command(ctx, "HDEL", s.prefix+"grants", stateHash(id))
	if e != nil {
		return e
	}
	if string(v) != "0" && string(v) != "1" {
		return ErrUnavailable
	}
	return nil
}

type refreshState struct {
	Refresh    Refresh `json:"refresh"`
	GrantHash  string  `json:"grant_hash"`
	FamilyHash string  `json:"family_hash"`
	Status     string  `json:"status"`
	Rotations  int     `json:"rotations"`
}

const refreshBindingLua = `local function scopes_equal(a,b) if #a~=#b then return false end; local set={}; for _,x in ipairs(a) do set[x]=true end; for _,x in ipairs(b) do if not set[x] then return false end end; return true end
local function bound(a,b) return a.subject==b.subject and a.client_id==b.client_id and a.resource==b.resource and scopes_equal(a.scopes,b.scopes) end
`
const createRefreshScript = refreshBindingLua + `local r=cjson.decode(ARGV[1]); local graw=redis.call('HGET',KEYS[1],r.grant_hash); if not graw then return 0 end; local g=cjson.decode(graw); if not bound(r.refresh,g) or r.refresh.grant_id~=g.id or r.refresh.expires_unix>g.expires_unix or r.refresh.expires_unix<=tonumber(ARGV[2]) then return 0 end; if g.refresh_family_hash or redis.call('EXISTS',KEYS[2])==1 or redis.call('EXISTS',KEYS[3])==1 then return -1 end; g.refresh_family_hash=r.family_hash; redis.call('HSET',KEYS[1],r.grant_hash,cjson.encode(g)); redis.call('SET',KEYS[2],ARGV[1],'EX',ARGV[3]); redis.call('SET',KEYS[3],ARGV[1],'EX',ARGV[3]); return 1`

func (s *RedisStore) CreateRefresh(ctx context.Context, token string, r Refresh) error {
	now := time.Now()
	if !validID(token) || !validID(r.FamilyID) || !validID(r.GrantID) || r.Subject != s.owner || !validID(r.ClientID) || !validID(r.Resource) || !validStateScopes(r.Scopes) || r.ExpiresUnix <= now.Unix() || r.ExpiresUnix > now.Add(maxStateTTL).Unix() {
		return errors.New("invalid refresh state")
	}
	rec := refreshState{Refresh: r, GrantHash: stateHash(r.GrantID), FamilyHash: stateHash(r.FamilyID), Status: "active"}
	raw, _ := json.Marshal(rec)
	if len(raw) > maxStateBytes {
		return errors.New("oversized refresh state")
	}
	v, e := s.command(ctx, "EVAL", createRefreshScript, 3, s.prefix+"grants", s.prefix+"refresh:"+stateHash(token), s.prefix+"family:"+rec.FamilyHash, string(raw), now.Unix(), r.ExpiresUnix-now.Unix())
	if e != nil {
		return e
	}
	switch string(v) {
	case "1":
		return nil
	case "0":
		return ErrNotFound
	case "-1":
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

// Every consumed hash remains as a spent tombstone until the original family
// deadline. Replay revokes both family and grant in the same Redis operation.
const rotateRefreshScript = refreshBindingLua + rateLimitLua + `local raw=redis.call('GET',KEYS[1]); if not raw then return {'missing',''} end; local r=cjson.decode(raw); local now=tonumber(ARGV[1]); if r.refresh.client_id~=ARGV[2] or r.refresh.resource~=ARGV[3] or r.refresh.subject~=ARGV[4] or r.refresh.expires_unix<=now then return {'missing',''} end; if r.family_hash~=ARGV[5] then return {'missing',''} end; local fkey=KEYS[4]; local fraw=redis.call('GET',fkey); if not fraw then return {'missing',''} end; local f=cjson.decode(fraw); if not bound(r.refresh,f.refresh) or r.refresh.family_id~=f.refresh.family_id or r.refresh.grant_id~=f.refresh.grant_id or r.refresh.expires_unix~=f.refresh.expires_unix then return {'missing',''} end; if r.status=='spent' then f.status='revoked'; redis.call('SET',fkey,cjson.encode(f),'EX',r.refresh.expires_unix-now); redis.call('HDEL',KEYS[3],r.grant_hash); return {'replay',''} end; if r.status~='active' or f.status~='active' then return {'missing',''} end; local graw=redis.call('HGET',KEYS[3],r.grant_hash); if not graw then return {'missing',''} end; local g=cjson.decode(graw); if not bound(r.refresh,g) or r.refresh.grant_id~=g.id or g.expires_unix<r.refresh.expires_unix or g.expires_unix<=now then return {'missing',''} end; if redis.call('EXISTS',KEYS[2])==1 then return {'conflict',''} end; if f.rotations>=tonumber(ARGV[6]) then f.status='revoked'; redis.call('SET',fkey,cjson.encode(f),'EX',r.refresh.expires_unix-now); redis.call('HDEL',KEYS[3],r.grant_hash); return {'missing',''} end; if not allow_rate(KEYS[5],tonumber(ARGV[7]),tonumber(ARGV[8])) then return {'limited',''} end; r.status='spent'; redis.call('SET',KEYS[1],cjson.encode(r),'EX',r.refresh.expires_unix-now); r.status='active'; f.rotations=f.rotations+1; redis.call('SET',KEYS[2],cjson.encode(r),'EX',r.refresh.expires_unix-now); redis.call('SET',fkey,cjson.encode(f),'EX',r.refresh.expires_unix-now); return {'ok',cjson.encode(r.refresh)}`

func (s *RedisStore) RotateRefresh(ctx context.Context, oldToken, newToken, clientID, resource string, now time.Time) (Refresh, error) {
	if !validID(oldToken) || !validID(newToken) || oldToken == newToken || !validID(clientID) || !validID(resource) {
		return Refresh{}, ErrNotFound
	}
	// Resolve only the family key in a read-only preflight, then re-read and
	// validate every claim inside the atomic script. Declaring all keys makes
	// the operation safe on cluster providers with the owner hash tag.
	oldKey := s.prefix + "refresh:" + stateHash(oldToken)
	preview, e := s.command(ctx, "GET", oldKey)
	if e != nil {
		return Refresh{}, e
	}
	previewRaw, e := decodeString(preview)
	if e != nil {
		return Refresh{}, e
	}
	var state refreshState
	if json.Unmarshal(previewRaw, &state) != nil || !validID(state.Refresh.FamilyID) || state.FamilyHash != stateHash(state.Refresh.FamilyID) || state.GrantHash != stateHash(state.Refresh.GrantID) {
		return Refresh{}, ErrUnavailable
	}
	v, e := s.command(ctx, "EVAL", rotateRefreshScript, 5, oldKey, s.prefix+"refresh:"+stateHash(newToken), s.prefix+"grants", s.prefix+"family:"+state.FamilyHash, s.prefix+"rate:"+stateHash(tokenRateBucket(state.Refresh.GrantID)), now.Unix(), clientID, resource, s.owner, state.FamilyHash, maxFamilyRotations, tokenGrantLimit, int64(time.Minute/time.Second))
	if e != nil {
		return Refresh{}, e
	}
	var parts []string
	if json.Unmarshal(v, &parts) != nil || len(parts) != 2 {
		return Refresh{}, ErrUnavailable
	}
	switch parts[0] {
	case "limited":
		return Refresh{}, ErrRateLimited
	case "missing":
		return Refresh{}, ErrNotFound
	case "replay":
		return Refresh{}, ErrReplay
	case "conflict":
		return Refresh{}, ErrConflict
	case "ok":
		var r Refresh
		if json.Unmarshal([]byte(parts[1]), &r) != nil || r.Subject != s.owner || r.ClientID != clientID || r.Resource != resource || r.ExpiresUnix <= now.Unix() || !validStateScopes(r.Scopes) {
			return Refresh{}, ErrUnavailable
		}
		return r, nil
	default:
		return Refresh{}, fmt.Errorf("%w: invalid rotation response", ErrUnavailable)
	}
}
