package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/dispatch"
)

const statusScope = "mail.read mail.send"

func prepareStatusFixture(t *testing.T, f *groupedAuthFixture, a *App, store *groupedStore) string {
	t.Helper()
	// Generated Message-IDs use the sender's example.com domain and random hex.
	// Give recipient canaries a distinct domain so suffixes such as "cc" cannot
	// accidentally match a legitimate Message-ID instead of leaked recipients.
	message := strings.ReplaceAll(groupedMessageJSON, "@example.com", "@privacy-fixture.test")
	status, out := f.call(t, a, statusScope, "mail_prepare", `{"action":"new","message":`+message+`}`)
	groupedResult(t, status, out)
	if len(store.record.Owner) != 64 || store.record.ExpiresUnix == 0 {
		t.Fatal("preparation omitted verified owner or expiry")
	}
	return fmt.Sprintf(`{"action":"send_status","prepared_id":%q}`, store.record.Message.ID)
}

func statusContent(t *testing.T, status int, out map[string]any) map[string]any {
	t.Helper()
	r := groupedResult(t, status, out)
	content, ok := r["structuredContent"].(map[string]any)
	if !ok {
		t.Fatal("missing status structured content", r)
	}
	return content
}

func TestSendStatusProtocolReadOnlyAndMinimal(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, state := range []string{"prepared", "sending", "accepted", "rejected", "unknown", "expired", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			args := prepareStatusFixture(t, f, a, store)
			store.record.Status = state
			if state == "expired" {
				store.record.Status = "prepared"
				store.record.ExpiresUnix = time.Now().Add(-time.Minute).Unix()
			}
			if state == "unavailable" {
				store.record.Owner = ""
			}
			if state == "accepted" || state == "rejected" || state == "unknown" {
				store.record.Detail = "acknowledgement"
			}
			if state == "rejected" {
				// Pin the former random collision: "bcc" and the suffix
				// "cc@example.com" are valid identifier content, not leaks.
				store.record.Message.MessageID = "<aabcc@example.com>"
			}
			before, _ := json.Marshal(store.record)
			a.EnableSend, a.EnableWrites = false, false
			status, out := f.call(t, a, statusScope, "mail_query", args)
			content := statusContent(t, status, out)
			if content["status"] != state || content["delivery_verified"] != false || content["retry_safe"] == true {
				t.Fatalf("incorrect status semantics: %#v", content)
			}
			warning, _ := content["warning"].(string)
			for _, text := range []string{"not delivery", "not proof of non-send", "Never automatically resend", "sending/unknown"} {
				if !strings.Contains(warning, text) {
					t.Fatalf("unsafe or incomplete receipt warning: %s", warning)
				}
			}
			allowed := map[string]bool{"status": true, "message_id": true, "stage": true, "expires_at": true, "delivery_verified": true, "warning": true}
			for k := range content {
				if !allowed[k] {
					t.Fatal("unexpected status field", k)
				}
			}
			if state == "unavailable" {
				if len(content) != 3 {
					t.Fatal("unavailable receipt included identifying data", content)
				}
			} else if content["message_id"] != store.record.Message.MessageID || content["expires_at"] == nil {
				t.Fatal("receipt missing Message-ID/expiry", content)
			}
			encoded, _ := json.Marshal(out)
			for _, canary := range []string{store.record.Message.Digest, "Exact body", "Original body", "Review me", "hidden@privacy-fixture.test", "to@privacy-fixture.test", "cc@privacy-fixture.test", "note.txt", "data_base64", "recipients", `"digest":`, `"bcc":`, `"raw":`, "text/plain", "grouped-test-owner"} {
				if strings.Contains(string(encoded), canary) {
					t.Fatalf("receipt leaked %q", canary)
				}
			}
			after, _ := json.Marshal(store.record)
			if !bytes.Equal(before, after) || store.puts != 1 || store.statuses != 1 || store.claims != 0 || store.completes != 0 || len(backend.calls) != 0 {
				t.Fatalf("status mutated or called mail: calls=%v statuses=%d", backend.calls, store.statuses)
			}
		})
	}
}

func TestSendStatusProtocolPrincipalIsolationAndClaimBinding(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, backend, store := newGroupedApp()
	args := prepareStatusFixture(t, f, a, store)
	owner := store.record.Owner
	status, out := f.callFor(t, a, statusScope, "grouped-test-other", "mail_query", args)
	foreign := statusContent(t, status, out)
	status, out = f.call(t, a, statusScope, "mail_query", `{"action":"send_status","prepared_id":"00000000000000000000000000000000"}`)
	missing := statusContent(t, status, out)
	store.record.Owner = ""
	status, out = f.call(t, a, statusScope, "mail_query", args)
	legacy := statusContent(t, status, out)
	if !reflect.DeepEqual(foreign, missing) || !reflect.DeepEqual(legacy, missing) || missing["status"] != "unavailable" {
		t.Fatal("foreign, missing and legacy IDs differ", foreign, missing, legacy)
	}
	store.record.Owner = owner
	sendArgs := fmt.Sprintf(`{"prepared_id":%q,"confirmed_digest":%q,"append_sent":false}`, store.record.Message.ID, store.record.Message.Digest)
	status, out = f.callFor(t, a, statusScope, "grouped-test-other", "mail_send_confirmed", sendArgs)
	groupedExpectError(t, status, out)
	if store.claimed || len(backend.calls) != 0 || store.completes != 0 {
		t.Fatal("foreign principal sent another owner's preparation")
	}
	status, out = f.call(t, a, statusScope, "mail_query", args)
	if content := statusContent(t, status, out); content["status"] != "prepared" {
		t.Fatal("unauthorized send consumed preparation", content)
	}
	status, out = f.call(t, a, statusScope, "mail_send_confirmed", sendArgs)
	groupedResult(t, status, out)
	if store.record.Owner != owner || !reflect.DeepEqual(backend.calls, []string{"send"}) {
		t.Fatal("authorized send lost owner or used unexpected backend", backend.calls)
	}
	status, out = f.callFor(t, a, statusScope, "grouped-test-other", "mail_query", args)
	if content := statusContent(t, status, out); !reflect.DeepEqual(content, foreign) {
		t.Fatal("completion exposed receipt to foreign owner", content)
	}
	status, out = f.call(t, a, statusScope, "mail_query", args)
	if content := statusContent(t, status, out); content["status"] != "accepted" || content["stage"] != "acknowledgement" {
		t.Fatal("completion receipt unavailable to owner", content)
	}
}

func TestSendStatusProtocolScopeChallenges(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, scope := range []string{"mail.read", "mail.read mail.write", "mail.send"} {
		t.Run(scope, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			status, out := f.call(t, a, scope, "mail_query", `{"action":"send_status","prepared_id":"00000000000000000000000000000000"}`)
			groupedExpectError(t, status, out)
			if scope == "mail.send" {
				if status != http.StatusForbidden {
					t.Fatal("missing base read scope admitted", status)
				}
			} else {
				meta := out["result"].(map[string]any)["_meta"].(map[string]any)
				challenge, _ := json.Marshal(meta["mcp/www_authenticate"])
				for _, required := range []string{"resource_metadata", "https://mail.example.com/.well-known/oauth-protected-resource", "mail.read mail.send"} {
					if !bytes.Contains(challenge, []byte(required)) {
						t.Fatalf("scope challenge missing %q: %s", required, challenge)
					}
				}
			}
			if len(backend.calls) != 0 || store.puts+store.claims+store.completes+store.statuses != 0 {
				t.Fatal("unauthorized status reached backend/store")
			}
		})
	}
	a, backend, _ := newGroupedApp()
	a.EnableSend = false
	status, out := f.call(t, a, "mail.read", "mail_query", `{"action":"folders"}`)
	groupedResult(t, status, out)
	if !reflect.DeepEqual(backend.calls, []string{"folders"}) {
		t.Fatal("ordinary query acquired send requirement")
	}
}

func TestSendStatusRejectsInvalidArgumentsBeforeStore(t *testing.T) {
	f := newGroupedAuthFixture(t)
	cases := []string{
		`{"action":"send_status"}`, `{"action":"send_status","prepared_id":null}`,
		`{"action":"send_status","prepared_id":""}`, `{"action":"send_status","prepared_id":"../bad"}`,
		`{"action":"send_status","prepared_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"action":"folders","prepared_id":"00000000000000000000000000000000"}`,
	}
	for _, extra := range []string{`"confirmed_digest":"x"`, `"append_sent":false`, `"owner":"x"`, `"subject":"x"`, `"search":{}`, `"reference":null`, `"detail":"full"`, `"index":0`, `"message":{}`} {
		cases = append(cases, `{"action":"send_status","prepared_id":"00000000000000000000000000000000",`+extra+`}`)
	}
	for _, args := range cases {
		t.Run(args, func(t *testing.T) {
			a, backend, store := newGroupedApp()
			status, out := f.call(t, a, statusScope, "mail_query", args)
			groupedExpectError(t, status, out)
			if len(backend.calls) != 0 || store.puts+store.claims+store.completes+store.statuses != 0 {
				t.Fatal("invalid arguments reached store/backend")
			}
		})
	}
}

type unavailableStatusStore struct{ *groupedStore }

func (s unavailableStatusStore) Status(context.Context, string, string, time.Time) (dispatch.SendStatus, error) {
	s.statuses++
	return dispatch.SendStatus{}, errors.New("durable send store unavailable")
}

func TestSendStatusStoreFailuresDoNotClaimOrSend(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, missing := range []bool{false, true} {
		a, backend, store := newGroupedApp()
		a.EnableSend = false
		if missing {
			a.Store = nil
		} else {
			a.Store = unavailableStatusStore{store}
		}
		status, out := f.call(t, a, statusScope, "mail_query", `{"action":"send_status","prepared_id":"00000000000000000000000000000000"}`)
		groupedExpectError(t, status, out)
		if len(backend.calls) != 0 || store.puts+store.claims+store.completes != 0 {
			t.Fatal("store failure triggered mutation or mail")
		}
	}
}

func TestAuthenticatedSendStatusDiscoveryKeepsSixReadOnlyTools(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, backend, store := newGroupedApp()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	r.Header.Set("Authorization", "Bearer "+f.token(t, "mail.read"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	f.auth.Middleware(a.Handler()).ServeHTTP(w, r)
	var response struct {
		Result struct {
			Tools []struct {
				Name        string                      `json:"name"`
				Annotations struct{ ReadOnlyHint bool } `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || len(response.Result.Tools) != 6 {
		t.Fatalf("discovery: %d %s %v", w.Code, w.Body.String(), err)
	}
	for _, tool := range response.Result.Tools {
		if tool.Name == "mail_query" && !tool.Annotations.ReadOnlyHint {
			t.Fatal("status changed query's read-only annotation")
		}
	}
	if len(backend.calls) != 0 || store.puts+store.claims+store.completes+store.statuses != 0 {
		t.Fatal("discovery entered backend/store")
	}
}

func TestTargetedSearchFieldsUseStrictQuerySchema(t *testing.T) {
	f := newGroupedAuthFixture(t)
	for _, field := range []string{"message_id", "participant"} {
		for _, invalid := range []string{"null", "1", "[]", "{}"} {
			a, backend, store := newGroupedApp()
			args := fmt.Sprintf(`{"action":"search","search":{"folder":"INBOX",%q:%s}}`, field, invalid)
			status, out := f.call(t, a, "mail.read", "mail_query", args)
			groupedExpectError(t, status, out)
			if len(backend.calls) != 0 || store.statuses != 0 {
				t.Fatal("invalid targeted search field reached backend/store")
			}
		}
	}
}
