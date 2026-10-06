package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"time"
)

const (
	maxJWKSBytes = 256 * 1024
	maxJWKSKeys = 32
	keyCacheTTL = 5 * time.Minute
	keyRefreshInterval = time.Minute
)

type verificationKey struct {
	algorithm string
	rsa *rsa.PublicKey
	ec *ecdsa.PublicKey
}

func (a *Authenticator) signingKey(ctx context.Context, kid, alg string) (verificationKey, error) {
	// Coalesce concurrent refreshes. The network call has both client and request
	// deadlines, so an attacker cannot leave the cache mutex held indefinitely.
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if key, found := a.keys[kid]; found && now.Before(a.keysExpire) {
		if key.algorithm != alg {
			return verificationKey{}, ErrInvalidToken
		}
		return key, nil
	}
	// Unknown kid values cannot induce one outbound request per bearer attempt.
	if !a.lastAttempt.IsZero() && now.Sub(a.lastAttempt) < keyRefreshInterval {
		return verificationKey{}, ErrInvalidToken
	}
	a.lastAttempt = now
	keys, err := a.fetchKeys(ctx)
	if err != nil {
		// Stale keys are never accepted on an unsuccessful refresh.
		return verificationKey{}, ErrInvalidToken
	}
	a.keys, a.keysExpire = keys, a.now().Add(keyCacheTTL)
	key, found := a.keys[kid]
	if !found || key.algorithm != alg {
		return verificationKey{}, ErrInvalidToken
	}
	return key, nil
}

func (a *Authenticator) fetchKeys(ctx context.Context) (map[string]verificationKey, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("JWKS endpoint did not return 200")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return nil, errors.New("JWKS response is unreadable or oversized")
	}
	return parseKeys(data)
}

func parseKeys(data []byte) (map[string]verificationKey, error) {
	object, err := jsonObject(data)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(object["keys"], &entries); err != nil || len(entries) == 0 || len(entries) > maxJWKSKeys {
		return nil, errors.New("invalid JWKS key count")
	}
	result := make(map[string]verificationKey)
	seen := make(map[string]struct{})
	for _, raw := range entries {
		entry, err := jsonObject(raw)
		if err != nil {
			return nil, err
		}
		kid, ok := stringValue(entry, "kid")
		if !ok || kid == "" || len(kid) > 256 {
			return nil, errors.New("JWKS key must have a bounded kid")
		}
		if _, duplicate := seen[kid]; duplicate {
			return nil, errors.New("JWKS kid must be unique")
		}
		seen[kid] = struct{}{}
		key, supported, err := parseKey(entry)
		if err != nil {
			return nil, err
		}
		if supported {
			result[kid] = key
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no supported JWKS signing keys")
	}
	return result, nil
}

func parseKey(entry map[string]json.RawMessage) (verificationKey, bool, error) {
	invalid := errors.New("invalid public signing key")
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, exists := entry[private]; exists {
			return verificationKey{}, false, invalid
		}
	}
	if _, exists := entry["use"]; exists {
		use, ok := stringValue(entry, "use")
		if !ok {
			return verificationKey{}, false, invalid
		}
		if use != "sig" {
			return verificationKey{}, false, nil
		}
	}
	if raw, exists := entry["key_ops"]; exists {
		var ops []string
		if json.Unmarshal(raw, &ops) != nil || len(ops) != 1 || ops[0] != "verify" {
			return verificationKey{}, false, nil
		}
	}
	kty, _ := stringValue(entry, "kty")
	alg := ""
	if _, exists := entry["alg"]; exists {
		var ok bool
		alg, ok = stringValue(entry, "alg")
		if !ok {
			return verificationKey{}, false, invalid
		}
	}
	switch kty {
	case "RSA":
		if alg != "" && alg != "RS256" {
			return verificationKey{}, false, nil
		}
		n, okN := decodedField(entry, "n")
		e, okE := decodedField(entry, "e")
		if !okN || !okE || len(n) == 0 || len(n) > 1024 || n[0] == 0 || len(e) == 0 || len(e) > 4 || e[0] == 0 {
			return verificationKey{}, false, invalid
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e).Int64()
		if modulus.BitLen() < 2048 || modulus.Bit(0) != 1 || exponent < 3 || exponent > 2147483647 || exponent%2 != 1 {
			return verificationKey{}, false, invalid
		}
		return verificationKey{algorithm: "RS256", rsa: &rsa.PublicKey{N: modulus, E: int(exponent)}}, true, nil
	case "EC":
		curve, ok := stringValue(entry, "crv")
		if !ok || curve != "P-256" || (alg != "" && alg != "ES256") {
			return verificationKey{}, false, nil
		}
		x, okX := decodedField(entry, "x")
		y, okY := decodedField(entry, "y")
		if !okX || !okY || len(x) != 32 || len(y) != 32 {
			return verificationKey{}, false, invalid
		}
		key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return verificationKey{}, false, invalid
		}
		return verificationKey{algorithm: "ES256", ec: key}, true, nil
	default:
		return verificationKey{}, false, nil
	}
}

func decodedField(entry map[string]json.RawMessage, name string) ([]byte, bool) {
	value, ok := stringValue(entry, name)
	if !ok {
		return nil, false
	}
	decoded, err := rawBase64.DecodeString(value)
	return decoded, err == nil
}
