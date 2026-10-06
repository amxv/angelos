package mail_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/app"
	"github.com/amxv/angelos/internal/auth"
	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/config"
	"github.com/amxv/angelos/internal/dispatch"
	"github.com/amxv/angelos/internal/mail"
	gomail "github.com/emersion/go-message/mail"
)

// These tests use the actual JWT verifier and MCP protocol boundary. No test-only
// principal injection or production authentication bypass is needed.
type integrationRoundTripper func(*http.Request) (*http.Response, error)

func (fn integrationRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type integrationAuthFixture struct {
	auth *auth.Authenticator
	key  *ecdsa.PrivateKey
}

func newIntegrationAuthFixture(t *testing.T) *integrationAuthFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "EC", "kid": "integration-test-key", "alg": "ES256", "use": "sig", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/jwks" {
			t.Errorf("unexpected JWKS request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials leaked to JWKS endpoint")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport
	gate, err := auth.New(auth.Config{
		ResourceURL: "https://mail.example.com/mcp", Issuer: "https://login.example.com/",
		JWKSURL: "https://login.example.com/jwks", AllowedSubjects: []string{"integration-test-owner"},
		HTTPClient: &http.Client{Transport: integrationRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://login.example.com/jwks" {
				return nil, fmt.Errorf("unexpected outbound URL: %s", r.URL)
			}
			local := r.Clone(r.Context())
			local.URL.Scheme, local.URL.Host = target.Scheme, target.Host
			local.Host = target.Host
			return transport.RoundTrip(local)
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &integrationAuthFixture{auth: gate, key: key}
}

func (f *integrationAuthFixture) token(t *testing.T, scope string) string {
	t.Helper()
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	now := time.Now()
	payload := encode(map[string]any{"alg": "ES256", "kid": "integration-test-key", "typ": "at+jwt"}) + "." + encode(map[string]any{
		"iss": "https://login.example.com/", "aud": "https://mail.example.com/mcp", "sub": "integration-test-owner",
		"scope": scope, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	digest := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *integrationAuthFixture) call(t *testing.T, a *app.App, scope, name, arguments string) (int, map[string]any) {
	t.Helper()
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":` + fmt.Sprintf("%q", name) + `,"arguments":` + arguments + `}}`
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/mcp", strings.NewReader(payload))
	r.Header.Set("Authorization", "Bearer "+f.token(t, scope))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	a.AuthChallenge = f.auth.Challenge
	f.auth.Middleware(a.Handler()).ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("HTTP %d: invalid JSON: %v: %s", w.Code, err, w.Body.String())
	}
	return w.Code, out
}

type integrationStore struct {
	messages []compose.Prepared
	claims   int
}

func (s *integrationStore) Put(_ context.Context, p compose.Prepared, owner string) error {
	s.messages = append(s.messages, p)
	return nil
}
func (s *integrationStore) Claim(context.Context, string, string, string, time.Time) (dispatch.Record, bool, error) {
	s.claims++
	return dispatch.Record{}, false, errors.New("fixture must not send")
}
func (s *integrationStore) Status(context.Context, string, string, time.Time) (dispatch.SendStatus, error) {
	return dispatch.SendStatus{}, errors.New("fixture must not inspect status")
}
func (s *integrationStore) Complete(context.Context, string, string, string) error {
	return errors.New("fixture must not send")
}

type integrationBackend struct {
	*mail.Backend
	sends int
}

func (b *integrationBackend) Send(context.Context, mail.Envelope, []byte) (mail.SendResult, error) {
	b.sends++
	return mail.SendResult{}, errors.New("fixture must not send")
}
func (b *integrationBackend) AppendSent(context.Context, []byte) (mail.MutationResult, error) {
	b.sends++
	return mail.MutationResult{}, errors.New("fixture must not write")
}

const integrationReference = `{"folder":"INBOX","uid_validity":7,"uid":2500}`

func rawCompositionFixture(subject string, longTo bool) string {
	to := "owner@example.com, alias@example.com, peer@example.com"
	if longTo {
		var people []string
		for i := 0; i < 35; i++ {
			people = append(people, strings.Repeat("Name ", 24)+fmt.Sprintf("<person%d@example.com>", i))
		}
		to += ", " + strings.Join(people, ",\r\n ")
	}
	return "From: =?UTF-8?Q?One=2C_Name?= <Author@Example.com>\r\n" +
		"Reply-To: First <ReplyFirst@Example.com>, Second <ReplySecond@Example.com>\r\n" +
		"To: " + to + "\r\nCc: copied@example.com\r\n" +
		"Bcc: private-original@example.com,\r\n private-other@example.com\r\n" +
		"Resent-Bcc: private-resent@example.com\r\n" +
		"Date: Fri, 2 Jan 2026 03:04:05 +0530\r\nSubject: " + subject + "\r\n" +
		"Message-ID: <CaseSensitive@Example.COM>\r\nReferences: <Root@Example.com> <root@Example.com>\r\n" +
		"Received: retained-original-trace\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=source-boundary\r\n\r\n" +
		"--source-boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOriginal body\r\n" +
		"--source-boundary\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Disposition: attachment; filename=source.txt\r\nContent-Transfer-Encoding: base64\r\n\r\naOk=\r\n" +
		"--source-boundary--\r\n"
}

func integrationResult(t *testing.T, status int, out map[string]any) map[string]any {
	t.Helper()
	r, ok := out["result"].(map[string]any)
	if status != http.StatusOK || !ok || out["error"] != nil || r["isError"] == true {
		t.Fatalf("tool failed HTTP %d: %#v", status, out)
	}
	return r["structuredContent"].(map[string]any)
}

func TestRealIMAPOAuthMCPComposition(t *testing.T) {
	f := newIntegrationAuthFixture(t)
	for _, tc := range []struct {
		name, action, options, subject string
		longTo                         bool
	}{
		{"reply_all_complete_headers", "reply_all", "", "=?UTF-8?Q?caf=C3=A9?=", true},
		{"eml_7bit", "forward", `,"original_mode":"eml"`, "ASCII original", false},
		{"eml_utf8_fallback", "forward", `,"original_mode":"eml"`, "café UTF-8 original", false},
		{"selected_attachment", "forward", `,"attachment_indexes":[1]`, "Attachment original", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := rawCompositionFixture(tc.subject, tc.longTo)
			backend, trace := mail.BackendForCompositionTesting(t, raw)
			b := &integrationBackend{Backend: backend}
			store := &integrationStore{}
			a := &app.App{Mail: b, Submitter: b, Store: store, EnableSend: true, Config: config.Config{From: "owner@example.com", Username: "owner@example.com", Aliases: []string{"alias@example.com"}}}
			message := `{"html":"<p>Authored &amp; exact</p>"}`
			if tc.action == "forward" {
				message = `{"to":["target@example.com"],"html":"<p>Authored &amp; exact</p>"}`
			}
			arguments := `{"action":"` + tc.action + `","reference":` + integrationReference + `,"message":` + message + tc.options + `}`
			for attempt := 0; attempt < 2; attempt++ {
				status, out := f.call(t, a, "mail.read mail.send", "mail_prepare", arguments)
				preview := integrationResult(t, status, out)
				p := store.messages[attempt]
				if p.Digest != compose.WireDigest(p.From, p.Recipients, p.Raw) || preview["text"] != p.Text || preview["html"] != p.HTML {
					t.Fatal("preview not bound to exact authored+quoted MIME")
				}
				if preview["source_message_id"] != "<CaseSensitive@Example.COM>" {
					t.Fatal("source ID case changed")
				}
				encoded, _ := json.Marshal(preview)
				for _, secret := range []string{"private-original@example.com", "private-other@example.com", "private-resent@example.com"} {
					if bytes.Contains(p.Raw, []byte(secret)) || bytes.Contains(encoded, []byte(secret)) {
						t.Fatalf("source BCC leaked: %s", secret)
					}
				}
				reader, err := gomail.CreateReader(bytes.NewReader(p.Raw))
				if err != nil {
					t.Fatal(err)
				}
				if tc.action == "reply_all" {
					if len(p.To) != 2 || len(p.Cc) != 37 || !strings.Contains(strings.Join(p.Cc, ","), "person34@example.com") {
						t.Fatalf("complete recipients not derived: To=%v Cc=%v", p.To, p.Cc)
					}
					if reader.Header.Get("In-Reply-To") != "<CaseSensitive@Example.COM>" || reader.Header.Get("References") != "<Root@Example.com> <root@Example.com> <CaseSensitive@Example.COM>" {
						t.Fatal("exact threading lost")
					}
					if !strings.Contains(p.Text, "One, Name <Author@Example.com> wrote:") || !strings.Contains(p.Text, "03:04 +0530") || p.Subject != "Re: café" {
						t.Fatalf("structured source/date decode wrong: %q", p.Text)
					}
					if len(p.Attachments) != 0 {
						t.Fatal("quoted reply included source attachment")
					}
				} else if reader.Header.Get("In-Reply-To") != "" || reader.Header.Get("References") != "" {
					t.Fatal("forward did not start new thread")
				}
				attachments := 0
				for {
					part, err := reader.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					data, err := io.ReadAll(part.Body)
					if err != nil {
						t.Fatal(err)
					}
					h, ok := part.Header.(*gomail.AttachmentHeader)
					if !ok {
						continue
					}
					attachments++
					ct, params, err := h.ContentType()
					if err != nil {
						t.Fatal(err)
					}
					if tc.name == "selected_attachment" {
						if ct != "text/plain" || params["charset"] != "iso-8859-1" {
							t.Fatalf("attachment Content-Type lost parameters: %s %v", ct, params)
						}
						// The high-level reader may charset-decode a text attachment;
						// validate byte identity against the frozen attachment hash.
						sum := sha256.Sum256([]byte{'h', 0xe9})
						if p.Attachments[0].SHA256 != fmt.Sprintf("%x", sum) {
							t.Fatal("source attachment charset bytes transcoded")
						}
						continue
					}
					want := strings.ReplaceAll(raw, "Bcc: private-original@example.com,\r\n private-other@example.com\r\n", "")
					want = strings.ReplaceAll(want, "Resent-Bcc: private-resent@example.com\r\n", "")
					if !bytes.Equal(data, []byte(want)) {
						t.Fatalf("EML bytes changed beyond outer BCC: %q", data)
					}
					wantType, wantCTE := "message/rfc822", "7bit"
					if tc.name == "eml_utf8_fallback" {
						wantType, wantCTE = "application/octet-stream", "base64"
					}
					if ct != wantType || h.Get("Content-Transfer-Encoding") != wantCTE {
						t.Fatalf("invalid attached-EML transport: %s %q", ct, h.Get("Content-Transfer-Encoding"))
					}
					if !strings.Contains(strings.Join(p.Warnings, " "), "embedded attachments are unchanged") {
						t.Fatal("EML metadata privacy disclosure missing")
					}
				}
				if (tc.action == "reply_all" && attachments != 0) || (tc.action == "forward" && attachments != 1) {
					t.Fatalf("wrong attachment count: %d", attachments)
				}
				if tc.action == "forward" && strings.HasPrefix(tc.name, "eml") && strings.Contains(p.Text, "Original body") {
					t.Fatal("EML mode silently quoted original")
				}
			}
			if b.sends != 0 || store.claims != 0 || len(store.messages) != 2 || store.messages[0].ID == store.messages[1].ID {
				t.Fatal("repeated preparation sent/reused content")
			}
			commands := trace()
			if !strings.Contains(commands, "EXAMINE ") || !strings.Contains(commands, "UID FETCH 2500") || !strings.Contains(commands, "BODY.PEEK[]<0.5242881>") || strings.Contains(commands, "SELECT ") {
				t.Fatalf("source read not exact/read-only: %s", commands)
			}
		})
	}
}
