package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSentFilingStepUpChallengeBeforeClaim(t *testing.T) {
	f := newGroupedAuthFixture(t)
	a, backend, store := newGroupedApp()
	a.AuthChallenge = f.auth.Challenge
	args := strings.Replace(groupedSeedSend(t, store), `"append_sent":false`, `"append_sent":true`, 1)
	status, out := f.call(t, a, "mail.read mail.send", "mail_send_confirmed", args)
	groupedExpectError(t, status, out)
	r := out["result"].(map[string]any)
	p := r["structuredContent"].(map[string]any)
	if p["error_code"] != "insufficient_scope" || !strings.Contains(p["error"].(string), "no message was sent") {
		t.Fatal(p)
	}
	challenge, _ := json.Marshal(r["_meta"].(map[string]any)["mcp/www_authenticate"])
	for _, required := range []string{"mail.read mail.write mail.send", "insufficient_scope", "error_description", "no message was sent"} {
		if !strings.Contains(string(challenge), required) {
			t.Fatal("incomplete conditional challenge", string(challenge))
		}
	}
	if len(backend.calls) != 0 || store.claims != 0 || store.completes != 0 {
		t.Fatal("step-up attempted send", backend.calls, store.claims)
	}
	if p["retry"].(map[string]any)["transport_retry_safe"] != false {
		t.Fatal("unsafe send retry hint")
	}
	// A server gate remains a deployment error, not an OAuth escalation prompt.
	a.EnableWrites = false
	status, out = f.call(t, a, "mail.read mail.send", "mail_send_confirmed", args)
	groupedExpectError(t, status, out)
	r = out["result"].(map[string]any)
	if r["_meta"] != nil || r["structuredContent"].(map[string]any)["error_code"] != "deployment_disabled" {
		t.Fatal("gate bypass through scope challenge", r)
	}
}
