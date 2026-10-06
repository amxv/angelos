package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestJWKRestrictions(t *testing.T) {
	rsa := rsaKey(t)
	for _, test := range []struct { name string; change func(map[string]any); valid bool }{
		{"valid RSA", func(k map[string]any) {}, true},
		{"algorithm inferred from key type", func(k map[string]any) { delete(k, "alg") }, true},
		{"explicit verification", func(k map[string]any) { k["key_ops"] = []string{"verify"} }, true},
		{"private material", func(k map[string]any) { k["d"] = "secret" }, false},
		{"symmetric material", func(k map[string]any) { k["k"] = "secret" }, false},
		{"algorithm conflict", func(k map[string]any) { k["alg"] = "ES256" }, false},
		{"symmetric algorithm", func(k map[string]any) { k["alg"] = "HS256" }, false},
		{"encryption key", func(k map[string]any) { k["use"] = "enc" }, false},
		{"signing operation", func(k map[string]any) { k["key_ops"] = []string{"sign"} }, false},
		{"both operations", func(k map[string]any) { k["key_ops"] = []string{"verify", "sign"} }, false},
		{"no kid", func(k map[string]any) { delete(k, "kid") }, false},
		{"empty kid", func(k map[string]any) { k["kid"] = "" }, false},
		{"no modulus", func(k map[string]any) { delete(k, "n") }, false},
		{"small modulus", func(k map[string]any) { k["n"] = rawBase64.EncodeToString(big.NewInt(65537).Bytes()) }, false},
		{"large modulus", func(k map[string]any) { k["n"] = rawBase64.EncodeToString(append([]byte{1}, make([]byte, 1024)...)) }, false},
		{"even modulus", func(k map[string]any) { n := append([]byte(nil), rsa.N.Bytes()...); n[len(n)-1] &^= 1; k["n"] = rawBase64.EncodeToString(n) }, false},
		{"zero exponent", func(k map[string]any) { k["e"] = "AA" }, false},
		{"even exponent", func(k map[string]any) { k["e"] = "Ag" }, false},
		{"oversized exponent", func(k map[string]any) { k["e"] = rawBase64.EncodeToString([]byte{1, 0, 0, 0, 1}) }, false},
		{"padded base64", func(k map[string]any) { k["e"] = "Aw==" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := publicRSA(rsa, "one")
			test.change(key)
			keys, err := parseKeys(jsonBytes(t, map[string]any{"keys": []any{key}}))
			if test.valid && (err != nil || len(keys) != 1) { t.Fatalf("valid key rejected: %v", err) }
			if !test.valid && err == nil { t.Fatal("invalid key accepted") }
		})
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	for _, test := range []struct { name string; change func(map[string]any) }{
		{"wrong curve", func(k map[string]any) { k["crv"] = "P-384" }},
		{"off-curve point", func(k map[string]any) { k["x"] = rawBase64.EncodeToString(make([]byte, 32)); k["y"] = rawBase64.EncodeToString(make([]byte, 32)) }},
		{"short coordinate", func(k map[string]any) { k["x"] = "AQ" }},
		{"missing coordinate", func(k map[string]any) { delete(k, "y") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := publicEC(ec, "ec")
			test.change(key)
			if _, err := parseKeys(jsonBytes(t, map[string]any{"keys": []any{key}})); err == nil { t.Fatal("invalid EC key accepted") }
		})
	}
}

func TestJWKSStructureRestrictions(t *testing.T) {
	key := publicRSA(rsaKey(t), "same")
	if _, err := parseKeys(jsonBytes(t, map[string]any{"keys": []any{key, key}})); err == nil { t.Fatal("duplicate kid accepted") }
	tooMany := make([]any, maxJWKSKeys+1)
	for i := range tooMany { tooMany[i] = key }
	for _, data := range [][]byte{
		[]byte(`{"keys":null}`), []byte(`{"keys":[]}`), []byte(`{"keys":[] ,"keys":[]}`), []byte(`{"keys":[null]}`), []byte(`{"KEYS":[]}`), []byte(`not json`),
		jsonBytes(t, map[string]any{"keys": tooMany}),
	} {
		if _, err := parseKeys(data); err == nil { t.Fatalf("invalid key set accepted: %.80s", data) }
	}
	unsupported := map[string]any{"kid": "unsupported", "kty": "OKP", "alg": "EdDSA"}
	if keys, err := parseKeys(jsonBytes(t, map[string]any{"keys": []any{unsupported, key}})); err != nil || len(keys) != 1 { t.Fatalf("supported key alongside unrelated key rejected: %v", err) }
}

func TestStrictJSONObject(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `"a"`, `{} {}`, `{"x":1,"x":2}`, `{"nested":{"x":1,"x":2}}`, `{"a":[{"x":1,"x":2}]}`, `{"unterminated":`,
		"{\"x\":\"\xff\"}", `{"a":`+strings.Repeat("[", 18)+`0`+strings.Repeat("]", 18)+`}`,
	} {
		if _, err := jsonObject([]byte(raw)); err == nil { t.Fatalf("invalid JSON accepted: %q", raw) }
	}
	if _, err := jsonObject([]byte(`{"a":[1,true,null,{"b":"c"}],"A":2}`)); err != nil { t.Fatalf("valid case-sensitive JSON rejected: %v", err) }
}

func FuzzJWTStructure(f *testing.F) {
	for _, token := range []string{"", "none", "a.b.c", "e30.e30.", strings.Repeat("x", 100)} { f.Add(token) }
	c := testConfig()
	a, err := New(c)
	if err != nil { f.Fatal(err) }
	// No network is reachable from the fuzz target. Its cache deliberately cannot
	// contain a key, so random structured tokens are always rejected locally.
	a.lastAttempt = a.now().Add(24 * time.Hour)
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > maxTokenBytes+1 { return }
		if _, err := a.verify(t.Context(), token); err == nil { t.Fatal("unsigned fuzz input authorized") }
	})
}

func FuzzJSONObject(f *testing.F) {
	for _, data := range []string{`{}`, `{"a":1}`, `{"a":1,"a":2}`, `[]`, `null`} { f.Add(data) }
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > maxTokenBytes { return }
		object, err := jsonObject([]byte(data))
		if err == nil && (object == nil || !json.Valid([]byte(data))) { t.Fatal("invalid JSON accepted") }
	})
}
