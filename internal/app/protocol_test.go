package app

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func callProtocol(t *testing.T, a *App, payload string) map[string]any {
	t.Helper()
	r := httptest.NewRequest("POST", "https://example.com/mcp", bytes.NewBufferString(payload))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("HTTP%d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e, w.Body.String())
	}
	return out
}
func TestActualToolRegistryAndAnnotations(t *testing.T) {
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	listed := out["result"].(map[string]any)["tools"].([]any)
	expected := map[string]struct {
		scope                   string
		read, destructive, open bool
		actions                 []string
	}{
		"mail_query":              {"mail.read", true, false, false, []string{"attachment", "capabilities", "conversation", "folders", "read", "read_many", "search", "send_status", "triage"}},
		"mail_create":             {"mail.write", false, false, false, []string{"copy", "draft", "folder"}},
		"mail_modify":             {"mail.write", false, true, false, []string{"flags", "move", "rename", "trash"}},
		"mail_delete_permanently": {"mail.write", false, true, false, nil},
		"mail_prepare":            {"mail.send", false, false, false, []string{"forward", "new", "reply", "reply_all"}},
		"mail_send_confirmed":     {"mail.send", false, true, true, nil},
	}
	if len(listed) != len(expected) {
		t.Fatalf("got %d tools, want %d", len(listed), len(expected))
	}
	for _, v := range listed {
		tool := v.(map[string]any)
		name := tool["name"].(string)
		want, ok := expected[name]
		if !ok {
			t.Fatal("unexpected tool", name)
		}
		delete(expected, name)
		ann := tool["annotations"].(map[string]any)
		if ann["readOnlyHint"] != want.read || ann["destructiveHint"] != want.destructive || ann["openWorldHint"] != want.open || ann["idempotentHint"] != false {
			t.Fatal(name, ann)
		}
		scheme := tool["_meta"].(map[string]any)["securitySchemes"].([]any)[0].(map[string]any)
		scopes := []any{"mail.read"}
		if want.scope != "mail.read" {
			scopes = append(scopes, want.scope)
		}
		if !reflect.DeepEqual(scheme["scopes"], scopes) {
			t.Fatal(name, scheme)
		}
		schema := tool["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatal(name, "allows unknown properties")
		}
		if want.actions != nil {
			enum := schema["properties"].(map[string]any)["action"].(map[string]any)["enum"].([]any)
			var got []string
			for _, v := range enum {
				got = append(got, v.(string))
			}
			if !reflect.DeepEqual(got, want.actions) {
				t.Fatal(name, got)
			}
		}
	}
}

func TestToolSchemaTokenBudget(t *testing.T) {
	baseline, e := os.ReadFile("testdata/tools-list-v0.1.0.json")
	if e != nil {
		t.Fatal(e)
	}
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	current, e := json.Marshal(out["result"].(map[string]any)["tools"])
	if e != nil {
		t.Fatal(e)
	}
	// Current ChatGPT clients require the top-level declaration in addition to
	// the legacy _meta mirror. Preserve the original structural budget and give
	// only that mandatory, tested compatibility duplication a bounded allowance.
	var structural []map[string]json.RawMessage
	if e := json.Unmarshal(current, &structural); e != nil {
		t.Fatal(e)
	}
	for _, tool := range structural {
		delete(tool, "securitySchemes")
	}
	withoutMirror, e := json.Marshal(structural)
	if e != nil {
		t.Fatal(e)
	}
	if len(withoutMirror)*100 > len(baseline)*70 || len(current)-len(withoutMirror) > 512 {
		t.Fatalf("discovery exceeds 70%% structural budget or 512-byte OAuth compatibility allowance: wire=%d structural=%d baseline=%d", len(current), len(withoutMirror), len(baseline))
	}
	countSchemas := func(raw []byte) (int, int) {
		var ts []map[string]json.RawMessage
		if e := json.Unmarshal(raw, &ts); e != nil {
			t.Fatal(e)
		}
		n := 0
		for _, tool := range ts {
			n += len(tool["inputSchema"])
		}
		return len(ts), n
	}
	oldCount, oldSchemas := countSchemas(baseline)
	newCount, newSchemas := countSchemas(current)
	t.Logf("tools: %d -> %d; tools/list tools array UTF-8 JSON bytes: %d -> %d; inputSchema bytes: %d -> %d; approximate tokens ceil(bytes/4), not a tokenizer: %d -> %d", oldCount, newCount, len(baseline), len(current), oldSchemas, newSchemas, (len(baseline)+3)/4, (len(current)+3)/4)
}
func TestMissingScopeReturnsChallengeWithoutBackend(t *testing.T) {
	a := &App{AuthChallenge: func(string) string { return `Bearer scope="mail.read mail.send"` }}
	out := callProtocol(t, a, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mail_send_confirmed","arguments":{"prepared_id":"x","confirmed_digest":"y","append_sent":false}}}`)
	r, ok := out["result"].(map[string]any)
	if !ok || r["isError"] != true {
		t.Fatal(out)
	}
	meta, ok := r["_meta"].(map[string]any)
	if !ok || meta["mcp/www_authenticate"] == nil {
		t.Fatal("missing OAuth challenge", out)
	}
}
