package mail

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/amxv/angelos/internal/config"
)

// MicrosoftTokenStoreClient is implemented by dispatch.Redis. Production uses
// its bounded, public-address-only HTTPS transport, never a separate Redis dial.
type MicrosoftTokenStoreClient interface {
	Command(context.Context, ...any) (json.RawMessage, error)
}

const maxMicrosoftStoredToken = 24 << 10

// The entire record is an authenticated encrypted refresh token. No mailbox
// address, account ID, credential or plaintext token is written to Redis.
type microsoftTokenStore struct {
	client MicrosoftTokenStoreClient
	aead   cipher.AEAD
	key    string
	config [32]byte
}

type microsoftStoredRefresh struct {
	encoded string // Exact ciphertext read, used as the compare-and-swap version.
	token   string
}

func microsoftStoreNamespace(c config.Config) string {
	initialHash := sha256.Sum256([]byte(c.MicrosoftRefreshToken))
	// JSON length framing prevents ambiguous owner identities. Changing the
	// initial refresh token explicitly starts a new authorization generation.
	binding, _ := json.Marshal([]string{c.MicrosoftTenantID, c.MicrosoftClientID,
		c.MicrosoftAccountID, c.From, hex.EncodeToString(initialHash[:])})
	digest := sha256.Sum256(binding)
	return "angelos:microsoft:refresh:v1:{" + hex.EncodeToString(digest[:]) + "}"
}

// ConfigureTokenStore attaches the durable encrypted store once, before use.
// A dedicated random 32-byte hex key is required. Replacing that key without
// migrating the existing record fails closed rather than reusing the env seed.
func (b *GraphBackend) ConfigureTokenStore(client MicrosoftTokenStoreClient) error {
	if client == nil {
		return ErrInvalidInput
	}
	v := reflect.ValueOf(client)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return ErrInvalidInput
		}
	}
	rawKey, err := hex.DecodeString(b.config.MicrosoftTokenEncryptionKey)
	if err != nil || len(rawKey) != 32 {
		return ErrInvalidInput
	}
	block, err := aes.NewCipher(rawKey)
	clear(rawKey)
	if err != nil {
		return ErrInvalidInput
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ErrInvalidInput
	}
	cache := &b.tokens
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if b.tokenStore != nil || cache.flight != nil || cache.token.value != "" {
		return ErrInvalidInput
	}
	b.tokenStore = &microsoftTokenStore{client: client, aead: aead,
		key: microsoftStoreNamespace(b.config), config: b.microsoftCredentialKey()}
	return nil
}

func (s *microsoftTokenStore) seal(token string) (string, error) {
	if !validMicrosoftRefreshToken(token) {
		return "", ErrUnavailable
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(token), []byte(s.key))
	return "v1." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *microsoftTokenStore) open(encoded string) (string, error) {
	if len(encoded) > maxMicrosoftStoredToken || !strings.HasPrefix(encoded, "v1.") {
		return "", ErrUnavailable
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(encoded, "v1."))
	if err != nil || len(sealed) <= s.aead.NonceSize()+s.aead.Overhead() {
		return "", ErrUnavailable
	}
	nonce := sealed[:s.aead.NonceSize()]
	plain, err := s.aead.Open(nil, nonce, sealed[s.aead.NonceSize():], []byte(s.key))
	if err != nil {
		return "", ErrUnavailable
	}
	token := string(plain)
	clear(plain)
	if !validMicrosoftRefreshToken(token) {
		return "", ErrUnavailable
	}
	return token, nil
}

func microsoftStoreError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

func (s *microsoftTokenStore) markerKey() string { return s.key + ":initialized" }

// Load both keys atomically and bound the reply inside Redis. A surviving
// initialization marker prevents bootstrap after loss of just the token record.
// Losing or rolling back the entire store cannot be detected by that same store.
const microsoftRefreshLoadScript = `local record=redis.call('GET',KEYS[1]); local marker=redis.call('GET',KEYS[2]);
if not record then if marker then return {2,''} end; return {0,''} end;
if marker~='v1' or string.len(record)>tonumber(ARGV[1]) then return {2,''} end;
return {1,record}`

func (s *microsoftTokenStore) load(ctx context.Context, seed string) (microsoftStoredRefresh, error) {
	if err := ctx.Err(); err != nil {
		return microsoftStoredRefresh{}, err
	}
	raw, err := s.client.Command(ctx, "EVAL", microsoftRefreshLoadScript, 2, s.key, s.markerKey(), maxMicrosoftStoredToken)
	if err != nil {
		return microsoftStoredRefresh{}, microsoftStoreError(ctx)
	}
	if len(raw) > maxMicrosoftStoredToken+32 {
		return microsoftStoredRefresh{}, ErrUnavailable
	}
	var parts []json.RawMessage
	if json.Unmarshal(raw, &parts) != nil || len(parts) != 2 {
		return microsoftStoredRefresh{}, ErrUnavailable
	}
	var state *int
	var encoded *string
	if json.Unmarshal(parts[0], &state) != nil || state == nil || json.Unmarshal(parts[1], &encoded) != nil || encoded == nil {
		return microsoftStoredRefresh{}, ErrUnavailable
	}
	if *state == 0 {
		if *encoded != "" || !validMicrosoftRefreshToken(seed) {
			return microsoftStoredRefresh{}, ErrUnavailable
		}
		return microsoftStoredRefresh{token: seed}, nil
	}
	if *state != 1 {
		return microsoftStoredRefresh{}, ErrUnavailable
	}
	token, err := s.open(*encoded)
	if err != nil {
		return microsoftStoredRefresh{}, ErrUnavailable
	}
	return microsoftStoredRefresh{encoded: *encoded, token: token}, nil
}

// Exact-ciphertext CAS prevents an old function from overwriting a newer
// rotation. Records deliberately have no TTL: expiry or eviction must not be
// used as a normal lifecycle mechanism for a durable OAuth refresh credential.
const microsoftRefreshCASScript = `local current=redis.call('GET',KEYS[1]); local marker=redis.call('GET',KEYS[2]);
if ARGV[1]=='' then if current or marker then return 0 end
elseif not current or current~=ARGV[1] or marker~='v1' then return 0 end;
redis.call('SET',KEYS[1],ARGV[2]); redis.call('SET',KEYS[2],'v1'); return 1`

func (s *microsoftTokenStore) advance(ctx context.Context, previous microsoftStoredRefresh, token string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	encoded, err := s.seal(token)
	if err != nil {
		return "", ErrUnavailable
	}
	raw, err := s.client.Command(ctx, "EVAL", microsoftRefreshCASScript, 2, s.key, s.markerKey(), previous.encoded, encoded)
	if err != nil {
		// An uncertain Redis commit never causes an automatic OAuth retry.
		return "", microsoftStoreError(ctx)
	}
	var changed *int
	if json.Unmarshal(raw, &changed) != nil || changed == nil || (*changed != 0 && *changed != 1) {
		return "", ErrUnavailable
	}
	if *changed == 1 {
		return token, nil
	}
	// Another instance won. Microsoft does not revoke an old refresh token
	// when it is used, so its persisted winner remains usable. Reread and
	// authenticate that winner; never overwrite it with this stale result.
	winner, err := s.load(ctx, "")
	if err != nil || winner.encoded == "" {
		return "", microsoftStoreError(ctx)
	}
	return winner.token, nil
}
