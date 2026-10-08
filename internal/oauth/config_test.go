package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

const passkeyRPID = "api.angelos.ashray.xyz"

var deploymentIssuers = []string{Issuer, "https://owner-mail.vercel.app", "https://mail.owner.example.com"}

func coreTestConfig(t *testing.T) Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Enabled: true, Issuer: Issuer, Resource: Resource, OwnerSubject: "test-owner", OwnerMailbox: "test@example.com", SigningKeyID: "test-key", SigningKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), Clients: []Client{{ID: "test-client", Name: "Test Client", RedirectURIs: []string{"https://client.example.com/callback"}}}}
}

func TestCoreConfigFailsClosed(t *testing.T) {
	base := coreTestConfig(t)
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"disabled", func(c *Config) { c.Enabled = false }},
		{"issuer resource mismatch", func(c *Config) { c.Issuer = "https://preview.example.com" }},
		{"resource slash", func(c *Config) { c.Resource = Resource + "/" }},
		{"owner missing", func(c *Config) { c.OwnerSubject = "" }},
		{"multiowner", func(c *Config) { c.OwnerSubject = "owner-a,owner-b" }},
		{"owner controls", func(c *Config) { c.OwnerSubject = "a\nb" }},
		{"mailbox missing", func(c *Config) { c.OwnerMailbox = "" }},
		{"mailbox display", func(c *Config) { c.OwnerMailbox = "Owner <owner@example.com>" }},
		{"private key missing", func(c *Config) { c.SigningKeyPEM = "" }},
		{"private key malformed", func(c *Config) { c.SigningKeyPEM = "unusable" }},
		{"key ID missing", func(c *Config) { c.SigningKeyID = "" }},
		{"bootstrap malformed", func(c *Config) { c.BootstrapTokenHash = "not-a-hash" }},
		{"clients missing", func(c *Config) { c.Clients = nil }},
		{"long client ID", func(c *Config) {
			c.Clients = []Client{{ID: strings.Repeat("a", 513), Name: "Client", RedirectURIs: []string{"https://client.example.com/callback"}}}
		}},
		{"duplicate client", func(c *Config) { c.Clients = append(c.Clients, c.Clients[0]) }},
		{"reserved client", func(c *Config) {
			c.Clients = []Client{{ID: ChatGPTClientID, Name: "ChatGPT", RedirectURIs: []string{ChatGPTRedirectURI}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := base
			test.change(&c)
			if _, err := New(c, newCoreMemoryStore()); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	if _, err := New(base, nil); err == nil {
		t.Fatal("nil store accepted")
	}
	var typedNil *RedisStore
	if _, err := New(base, typedNil); err == nil {
		t.Fatal("typed nil store accepted")
	}
	if _, err := New(base, newCoreMemoryStore()); err != nil {
		t.Fatal(err)
	}
}

func TestCoreConfigFromEnv(t *testing.T) {
	c := coreTestConfig(t)
	t.Setenv("ANGELOS_OAUTH_ENABLED", "")
	if _, err := ConfigFromEnv(); err != ErrDisabled {
		t.Fatalf("disabled result: %v", err)
	}
	for name, value := range map[string]string{
		"ANGELOS_OAUTH_ENABLED": "1", "MCP_OAUTH_ISSUER": Issuer, "MCP_RESOURCE_URL": Resource, "MCP_OAUTH_JWKS_URL": Issuer + JWKSPath,
		"MCP_ALLOWED_SUBJECTS": c.OwnerSubject, "MAIL_FROM": c.OwnerMailbox, "ANGELOS_OAUTH_SIGNING_KEY_PEM": c.SigningKeyPEM, "ANGELOS_OAUTH_SIGNING_KEY_ID": c.SigningKeyID,
		"ANGELOS_OAUTH_CLIENTS_JSON": "", "ANGELOS_OAUTH_VERIFICATION_KEYS_JSON": "", "ANGELOS_OAUTH_BOOTSTRAP_TOKEN_HASH": "", "ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED": "1",
	} {
		t.Setenv(name, value)
	}
	if got, err := ConfigFromEnv(); err != nil || !got.EnableChatGPTCIMD {
		t.Fatalf("valid config: %v", err)
	}
	t.Setenv("MCP_OAUTH_JWKS_URL", "https://other.example.com/keys")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("foreign keys accepted")
	}
	t.Setenv("MCP_OAUTH_JWKS_URL", Issuer+JWKSPath)
	raw, _ := json.Marshal(c.Clients)
	t.Setenv("ANGELOS_OAUTH_CLIENTS_JSON", string(raw))
	t.Setenv("ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED", "")
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANGELOS_OAUTH_CLIENTS_JSON", `[{"client_id":"one","client_id":"two"}]`)
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("ambiguous clients JSON accepted")
	}
}

func TestCoreRedirectAndScopeValidation(t *testing.T) {
	for _, raw := range []string{"http://client.example.com/callback", "https://client.example.com/callback#x", "https://user@client.example.com/callback", "https://client.example.com:444/cb", "https://127.0.0.1/cb", "https://service.local/cb", "https://client.example.com/a/../cb", "https://client.example.com/%2fcb", "https://client.example.com/cb?code=old", "https://client.example.com/cb?iss=bad", "https://client.example.com/cb?state=old", "https://client.example.com\\@evil.com/cb", "https://client.example.com:/cb"} {
		if validRedirect(raw) {
			t.Errorf("unsafe redirect accepted: %s", raw)
		}
	}
	if !validRedirect("https://client.example.com/callback?fixed=1") {
		t.Fatal("exact query callback rejected")
	}
	for _, scope := range []string{"", ScopeWrite, "mail.read mail.read", "mail.read openid", "mail.read\tmail.send", " mail.read", "mail.read ", "mail.read  mail.send"} {
		if _, err := parseScopes(scope); err == nil {
			t.Errorf("invalid scope accepted: %q", scope)
		}
	}
	got, err := parseScopes("mail.send mail.read mail.write")
	if err != nil || strings.Join(got, " ") != "mail.read mail.write mail.send" {
		t.Fatalf("scope canonicalization %v %v", got, err)
	}
}

func TestCoreStrictJSON(t *testing.T) {
	for _, input := range []string{`{"a":1,"a":2}`, `{"a":1,"A":2}`, `{"bootstrap_token":"first","bootſtrap_token":"second"}`, `{"key":1,"Key":2}`, `{"nested":{"a":1,"a":2}}`, `[{"a":1,"a":2}]`, `{} {}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		var out any
		if strictJSON([]byte(input), &out) == nil {
			t.Errorf("ambiguous JSON accepted: %s", input)
		}
	}
	var out any
	if err := strictJSON([]byte(`{"valid":[1,true,null,{"key":"value"}]}`), &out); err != nil {
		t.Fatal(err)
	}
}
