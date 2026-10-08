package app

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func discoveryTools(t *testing.T) []any {
	t.Helper()
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	return out["result"].(map[string]any)["tools"].([]any)
}

func expandDiscovery(v any, root map[string]any) any {
	switch v := v.(type) {
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = expandDiscovery(item, root)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		if ref, ok := v["$ref"].(string); ok {
			var resolved any = root
			for _, key := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
				resolved = resolved.(map[string]any)[key]
			}
			out = expandDiscovery(resolved, root).(map[string]any)
		}
		for k, item := range v {
			if k != "$ref" && k != "$defs" {
				out[k] = expandDiscovery(item, root)
			}
		}
		return out
	default:
		return v
	}
}

func TestDiscoveryUsabilityAndSize(t *testing.T) {
	current := discoveryTools(t)
	expanded := expandToolDiscovery(current)
	for _, raw := range expanded {
		tool := raw.(map[string]any)
		schema := tool["inputSchema"].(map[string]any)
		props := schema["properties"].(map[string]any)
		for key, raw := range props {
			field := raw.(map[string]any)
			if _, multi := field["type"].([]any); multi {
				t.Fatalf("top-level %s.%s advertises null", tool["name"], key)
			}
			if key == "message" || key == "changes" {
				for nested, v := range field["properties"].(map[string]any) {
					if _, multi := v.(map[string]any)["type"].([]any); multi {
						t.Fatalf("%s.%s.%s advertises null", tool["name"], key, nested)
					}
				}
			}
		}
		data, _ := json.Marshal(tool)
		var want []string
		switch tool["name"] {
		case "mail_query":
			want = []string{"page folder/uid_validity + row uid", "zero-based next_index", "query=literal text", "YYYY-MM-DD inclusive/exclusive", "same filters/order, even empty pages"}
		case "mail_create":
			want = []string{"mail_query draft source_digest for this ref", "explicitly set/clear both existing alternatives"}
		case "mail_modify":
			want = []string{`\\Seen=read`, `\\Flagged=starred`, "Observed modseq"}
		case "mail_prepare":
			want = []string{"omit for eml/none", "new/forward need recipients", "never Bcc"}
		case "mail_send_confirmed":
			want = []string{"digest from the approved mail_prepare preview", "False if mail_query capabilities says smtp_stores_sent (Gmail)", "not delivery", "never resend/duplicate"}
		}
		for _, needle := range want {
			if !strings.Contains(string(data), needle) {
				t.Fatalf("%s lacks %q", tool["name"], needle)
			}
		}
	}
	before, err := os.ReadFile("testdata/tools-list-v0.8.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var old []any
	if err = json.Unmarshal(before, &old); err != nil {
		t.Fatal(err)
	}
	oldJSON, _ := json.Marshal(old)
	newJSON, _ := json.Marshal(current)
	oldExpanded, _ := json.Marshal(expandToolDiscovery(old))
	newExpanded, _ := json.Marshal(expanded)
	if len(newJSON) > len(oldJSON) || len(newExpanded) > len(oldExpanded) {
		t.Fatalf("first-use discovery grew: JSON %d -> %d; expanded %d -> %d", len(oldJSON), len(newJSON), len(oldExpanded), len(newExpanded))
	}
	t.Logf("Complete six-tool JSON bytes: %d -> %d; locally expanded $ref bytes: %d -> %d (not tokenizer or connector measurements)", len(oldJSON), len(newJSON), len(oldExpanded), len(newExpanded))
}

func expandToolDiscovery(tools []any) []any {
	out := make([]any, len(tools))
	for i, raw := range tools {
		tool := raw.(map[string]any)
		copy := map[string]any{}
		for k, v := range tool {
			copy[k] = v
		}
		copy["inputSchema"] = expandDiscovery(tool["inputSchema"], tool["inputSchema"].(map[string]any))
		out[i] = copy
	}
	return out
}
