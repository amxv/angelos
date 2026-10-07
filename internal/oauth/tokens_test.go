package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCoreJWTProfileAndStableKeys(t *testing.T) {
	c := coreTestConfig(t)
	keys, e := loadSigningKeys(c)
	if e != nil {
		t.Fatal(e)
	}
	second, e := loadSigningKeys(c)
	if e != nil || string(keys.jwks) != string(second.jwks) {
		t.Fatal("cold start changed keys", e)
	}
	s, m := coreServer(t)
	p, _ := coreCode(t, s)
	w := coreToken(s, p)
	out := coreTokenValues(t, w)
	token := out["access_token"].(string)
	claims := coreClaims(t, token)
	if claims.Issuer != Issuer || claims.Audience != Resource || claims.Subject != s.config.OwnerSubject || claims.Expires-claims.Issued != 300 || !validOpaque(claims.ID) || !validOpaque(claims.GrantID) || claims.ClientID != p.Get("client_id") || claims.TokenUse != "access" || claims.Scope != "mail.read mail.send" {
		t.Fatal("invalid access claims", claims)
	}
	if out["expires_in"] != float64(300) || out["token_type"] != "Bearer" || !validOpaque(out["refresh_token"].(string)) {
		t.Fatal("bad token response", out)
	}
	parts := strings.Split(token, ".")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || len(signature) != 64 || !ecdsa.Verify(&s.keys.private.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("invalid access signature", e)
	}
	var header map[string]string
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if json.Unmarshal(raw, &header) != nil || header["alg"] != "ES256" || header["kid"] != s.config.SigningKeyID || header["typ"] != "at+jwt" {
		t.Fatal("invalid access header", header)
	}
	for _, tc := range []struct {
		gid, client, subject string
		scopes               []string
	}{{claims.GrantID, claims.ClientID, "other-owner", []string{ScopeRead}}, {claims.GrantID, "other-client", claims.Subject, []string{ScopeRead}}, {claims.GrantID, claims.ClientID, claims.Subject, []string{ScopeRead, ScopeWrite}}, {"short", claims.ClientID, claims.Subject, []string{ScopeRead}}} {
		if s.GrantActive(context.Background(), tc.gid, tc.client, tc.subject, tc.scopes) == nil {
			t.Fatal("foreign grant binding accepted", tc)
		}
	}
	g := m.grants[claims.GrantID]
	g.Scopes = []string{ScopeRead}
	m.grants[claims.GrantID] = g
	if s.GrantActive(context.Background(), claims.GrantID, claims.ClientID, claims.Subject, []string{ScopeRead, ScopeSend}) == nil {
		t.Fatal("narrowed grant still permits send")
	}
}

func TestCoreSigningKeyRotationAndInvalidKeys(t *testing.T) {
	c := coreTestConfig(t)
	old, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(&old.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	c.VerificationKeysPEM = map[string]string{"retiring": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	keys, e := loadSigningKeys(c)
	if e != nil {
		t.Fatal(e)
	}
	var jwks struct {
		Keys []publicJWK `json:"keys"`
	}
	if json.Unmarshal(keys.jwks, &jwks) != nil || len(jwks.Keys) != 2 || jwks.Keys[1].Kid != "retiring" {
		t.Fatal("rotation key missing", string(keys.jwks))
	}
	for _, test := range []struct {
		name  string
		alter func(*Config)
	}{
		{"private retiring key", func(c *Config) { c.VerificationKeysPEM = map[string]string{"old": c.SigningKeyPEM} }},
		{"duplicate kid", func(c *Config) {
			c.VerificationKeysPEM = map[string]string{c.SigningKeyID: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
		}},
		{"trailing PEM", func(c *Config) { c.SigningKeyPEM += c.SigningKeyPEM }},
		{"wrong curve", func(c *Config) {
			key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			raw, _ := x509.MarshalPKCS8PrivateKey(key)
			c.SigningKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := c
			test.alter(&copy)
			if _, e := New(copy, newCoreMemoryStore()); e == nil {
				t.Fatal("invalid signing config accepted")
			}
		})
	}
}

func TestCorePKCENoDowngradeAndAuthorizationScopeApproval(t *testing.T) {
	verifier := strings.Repeat("x", 43)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if !verifyPKCE(verifier, challenge) {
		t.Fatal("valid PKCE rejected")
	}
	for _, value := range []string{"", strings.Repeat("x", 42), strings.Repeat("x", 129), strings.Repeat("x", 43) + "=", strings.Repeat("x", 43) + " ", strings.Repeat("x", 43) + "\n"} {
		if verifyPKCE(value, challenge) {
			t.Fatal("invalid verifier accepted")
		}
	}
	s, _ := coreServer(t)
	a, _ := coreAuthorization(s)
	if _, e := s.ApproveAuthorization(context.Background(), a, "another-owner", a.Scopes); e == nil {
		t.Fatal("foreign owner accepted")
	}
	if _, e := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, []string{ScopeRead, ScopeWrite}); e == nil {
		t.Fatal("unrequested scope approved")
	}
	if _, e := s.ApproveAuthorization(context.Background(), a, s.config.OwnerSubject, nil); e == nil {
		t.Fatal("empty consent approved")
	}
	if expiresIn(time.Unix(100, 0), 200) != 100 || expiresIn(time.Unix(100, 0), 1000) != 300 {
		t.Fatal("access lifetime bound")
	}
}
