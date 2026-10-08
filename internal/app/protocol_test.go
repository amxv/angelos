package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
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

// Vercel may pass its public Host through a loopback connection to a function.
// The MCP SDK's default local-server DNS-rebinding protection rejects such a
// request before tools/list executes. Keep that protection on the default
// handler; production can opt out only behind the separate canonical-host gate.
func TestDefaultMCPTransportRejectsLoopbackWithPublicHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://api.angelos.ashray.xyz/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
	w := httptest.NewRecorder()
	(&App{}).Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !bytes.Contains(w.Body.Bytes(), []byte("Forbidden: invalid Host header")) {
		t.Fatalf("expected SDK loopback DNS rebinding protection to reject public Host before discovery: HTTP %d %s", w.Code, w.Body.String())
	}
}
func TestActualToolRegistryAndAnnotations(t *testing.T) {
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	listed := out["result"].(map[string]any)["tools"].([]any)
	expected := map[string]struct {
		scope                   string
		read, destructive, open bool
		actions                 []string
	}{
		"mail_query":              {"mail.read", true, false, false, []string{"attachment", "capabilities", "conversation", "draft", "folders", "read", "read_many", "search", "send_status", "triage"}},
		"mail_create":             {"mail.write", false, false, false, []string{"copy", "draft", "folder", "revise_draft"}},
		"mail_modify":             {"mail.write", false, true, false, []string{"flags", "move", "rename", "trash"}},
		"mail_delete_permanently": {"mail.write", false, true, false, nil},
		"mail_prepare":            {"mail.send", false, false, false, []string{"draft", "forward", "new", "reply", "reply_all"}},
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
	// 0.8 adds three bounded draft actions and a shared message/changes $defs.
	// Structural bytes: 10,341 (0.7) -> 11,004; complete wire: 11,433.
	// Preserve the old compression ceiling plus a fixed 768-byte lifecycle
	// allowance; never change the original 17-tool baseline to fit growth.
	const draftLifecycleAllowance = 768
	if (len(withoutMirror)-draftLifecycleAllowance)*100 > len(baseline)*70 || len(current)-len(withoutMirror) > 512 {
		t.Fatalf("discovery exceeds historic 70%% + 768-byte draft budget or 512-byte OAuth compatibility allowance: wire=%d structural=%d baseline=%d", len(current), len(withoutMirror), len(baseline))
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
	t.Logf("tools: %d -> %d; tools/list tools array UTF-8 JSON bytes: %d -> %d; inputSchema bytes: %d -> %d", oldCount, newCount, len(baseline), len(current), oldSchemas, newSchemas)
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

// Keep a complete release snapshot in addition to the historical compression
// budget. Updating it is intentional: UPDATE_TOOL_SNAPSHOT=1 go test -run
// TestToolSchemaReleaseSnapshot ./internal/app (with the configured toolchain).
func TestToolSchemaReleaseSnapshot(t *testing.T) {
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	data, err := json.Marshal(out["result"].(map[string]any)["tools"])
	if err != nil {
		t.Fatal(err)
	}
	path := "testdata/tools-list-v0.9.0.json"
	if os.Getenv("UPDATE_TOOL_SNAPSHOT") == "1" {
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), data) {
		t.Fatal("tool schema changed; review and intentionally update the 0.9.0 snapshot")
	}
}
