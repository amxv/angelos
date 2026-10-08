package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"
)

type signingKeys struct {
	private *ecdsa.PrivateKey
	kid     string
	jwks    []byte
}

type publicJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func loadSigningKeys(c Config) (signingKeys, error) {
	block, rest := pem.Decode([]byte(c.SigningKeyPEM))
	if block == nil || strings.TrimSpace(string(rest)) != "" || len(block.Headers) != 0 {
		return signingKeys{}, errors.New("invalid signing private key PEM")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return signingKeys{}, errors.New("invalid PKCS8 signing key")
		}
		key, _ = parsed.(*ecdsa.PrivateKey)
	case "EC PRIVATE KEY":
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return signingKeys{}, errors.New("invalid EC signing key")
		}
	default:
		return signingKeys{}, errors.New("signing key must be an unencrypted PKCS8 or EC private key")
	}
	if key == nil || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(key.Params().N) >= 0 {
		return signingKeys{}, errors.New("ES256 requires a P-256 signing key")
	}
	// Validate private/public consistency rather than publishing an unusable key.
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return signingKeys{}, errors.New("inconsistent signing key")
	}
	keys := []publicJWK{jwk(c.SigningKeyID, &key.PublicKey)}
	ids := make([]string, 0, len(c.VerificationKeysPEM))
	for id := range c.VerificationKeysPEM {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		block, rest := pem.Decode([]byte(c.VerificationKeysPEM[id]))
		if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" || len(block.Headers) != 0 {
			return signingKeys{}, errors.New("retiring signing keys must be public PKIX PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return signingKeys{}, errors.New("invalid retiring signing public key")
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return signingKeys{}, errors.New("retiring signing keys must be P-256")
		}
		keys = append(keys, jwk(id, pub))
	}
	encoded, err := json.Marshal(struct {
		Keys []publicJWK `json:"keys"`
	}{keys})
	if err != nil {
		return signingKeys{}, errors.New("cannot publish signing keys")
	}
	return signingKeys{private: key, kid: c.SigningKeyID, jwks: encoded}, nil
}

func jwk(id string, key *ecdsa.PublicKey) publicJWK {
	return publicJWK{Kty: "EC", Use: "sig", Alg: "ES256", Kid: id, Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
}

type accessClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	ID       string `json:"jti"`
	Scope    string `json:"scope"`
	GrantID  string `json:"gid"`
	ClientID string `json:"client_id"`
	TokenUse string `json:"token_use"`
}

func (s *Server) signAccess(grant Grant, scopes []string) (string, error) {
	now := s.now()
	if grant.Subject != s.config.OwnerSubject || grant.Resource != s.config.Resource || grant.ExpiresUnix <= now.Unix() || !scopeSubset(scopes, grant.Scopes) {
		return "", errors.New("invalid grant")
	}
	if _, err := canonicalScopes(scopes); err != nil {
		return "", err
	}
	jti, err := opaqueToken()
	if err != nil {
		return "", err
	}
	exp := now.Add(AccessTTL).Unix()
	if grant.ExpiresUnix < exp {
		exp = grant.ExpiresUnix
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": s.keys.kid, "typ": "at+jwt"})
	payload, _ := json.Marshal(accessClaims{Issuer: s.config.Issuer, Audience: s.config.Resource, Subject: grant.Subject, Expires: exp, Issued: now.Unix(), ID: jti, Scope: strings.Join(scopes, " "), GrantID: grant.ID, ClientID: grant.ClientID, TokenUse: "access"})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, ss, err := ecdsa.Sign(rand.Reader, s.keys.private, digest[:])
	if err != nil {
		return "", errors.New("access token signing unavailable")
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// GrantActive is called only after the resource server verifies the JWT's
// signature and claims. It deliberately performs a durable check on each use.
// Revocation, refresh replay, and disabling a configured client therefore
// invalidate existing access tokens too. Metadata uptime is not an access gate.
func (s *Server) GrantActive(ctx context.Context, grantID, clientID, subject string, scopes []string) error {
	if !validOpaque(grantID) || subject != s.config.OwnerSubject || !boundedText(clientID, 512) || !s.knownClient(clientID) {
		return ErrNotFound
	}
	if _, err := canonicalScopes(scopes); err != nil {
		return ErrNotFound
	}
	grant, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if grant.ID != grantID || grant.Subject != subject || grant.ClientID != clientID || grant.Resource != s.config.Resource || grant.ExpiresUnix <= s.now().Unix() || !scopeSubset(scopes, grant.Scopes) {
		return ErrNotFound
	}
	return nil
}

func opaqueToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validOpaque(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32 && len(value) == 43
}

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && !strings.ContainsRune("-._~", c) {
			return false
		}
	}
	return true
}

func verifyPKCE(verifier, challenge string) bool {
	if !validVerifier(verifier) || !validOpaque(challenge) {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}

func expiresIn(now time.Time, expires int64) int64 {
	remaining := expires - now.Unix()
	if remaining > int64(AccessTTL/time.Second) {
		return int64(AccessTTL / time.Second)
	}
	return remaining
}
