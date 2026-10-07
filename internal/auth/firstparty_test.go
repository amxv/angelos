package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestFirstPartyGrantBoundary(t *testing.T) {
	c := testConfig()
	c.LocalJWKS = jsonBytes(t, map[string]any{"keys": []any{publicRSA(rsaKey(t), "key-1")}})
	checks := 0
	revoked := false
	c.CheckGrant = func(ctx context.Context, grant, client, owner string, scopes []string) error {
		checks++
		if grant != "grant-fixture" || client != "client-fixture" || owner != "owner-123" || !reflect.DeepEqual(scopes, []string{ScopeRead}) {
			t.Errorf("wrong verified grant boundary: %q %q %q %v", grant, client, owner, scopes)
		}
		if revoked {
			return errors.New("revoked or unavailable")
		}
		return nil
	}
	f := newFixtureWithConfig(t, c)
	claims := func() map[string]any {
		v := f.claims()
		v["iat"] = f.now.Unix()
		v["exp"] = f.now.Add(5 * time.Minute).Unix()
		v["gid"], v["client_id"], v["jti"], v["scope"] = "grant-fixture", "client-fixture", "token-fixture", ScopeRead
		return v
	}
	valid := rsaToken(t, f.key, tokenHeader(), claims())
	if w := call(f.a, valid); w.Code != http.StatusNoContent || checks != 1 || f.requests.Load() != 0 {
		t.Fatalf("valid first party: status=%d checks=%d network=%d", w.Code, checks, f.requests.Load())
	}
	// Local public key input is copied at construction; callers cannot mutate it.
	for i := range c.LocalJWKS {
		c.LocalJWKS[i] = 0
	}
	f.a.keysExpire = time.Time{}
	f.a.lastAttempt = time.Time{}
	if w := call(f.a, valid); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	revoked = true
	if w := call(f.a, valid); w.Code != http.StatusUnauthorized {
		t.Fatal("revocation/store failure accepted", w.Code)
	}
	revoked = false
	for name, change := range map[string]func(map[string]any){
		"missing grant":   func(v map[string]any) { delete(v, "gid") },
		"missing client":  func(v map[string]any) { delete(v, "client_id") },
		"missing jti":     func(v map[string]any) { delete(v, "jti") },
		"missing iat":     func(v map[string]any) { delete(v, "iat") },
		"long lifetime":   func(v map[string]any) { v["exp"] = f.now.Add(301 * time.Second).Unix() },
		"audience array":  func(v map[string]any) { v["aud"] = []string{c.ResourceURL} },
		"unknown scope":   func(v map[string]any) { v["scope"] = ScopeRead + " admin" },
		"duplicate scope": func(v map[string]any) { v["scope"] = ScopeRead + " " + ScopeRead },
		"empty scope":     func(v map[string]any) { v["scope"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v := claims()
			change(v)
			before := checks
			if w := call(f.a, rsaToken(t, f.key, tokenHeader(), v)); w.Code != http.StatusUnauthorized || checks != before {
				t.Fatalf("malformed token accepted/reached grant store: %d checks=%d", w.Code, checks-before)
			}
		})
	}
	before := checks
	bad := valid[:len(valid)-10] + "xxxxxxxxxx"
	if w := call(f.a, bad); w.Code != http.StatusUnauthorized || checks != before {
		t.Fatal("unverified token reached grant store")
	}
}

func TestLocalJWKSRejectsMalformedOrPrivateKeys(t *testing.T) {
	for _, value := range [][]byte{[]byte(`{"keys":[]}`), []byte(`{}`), make([]byte, maxJWKSBytes+1)} {
		c := testConfig()
		c.LocalJWKS = value
		if _, err := New(c); err == nil {
			t.Fatal("invalid local key set accepted")
		}
	}
	k := publicRSA(rsaKey(t), "key-1")
	k["d"] = "not-allowed"
	c := testConfig()
	c.LocalJWKS = jsonBytes(t, map[string]any{"keys": []any{k}})
	if _, err := New(c); err == nil {
		t.Fatal("private key accepted")
	}
}
