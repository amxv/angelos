package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestOAuthDiscoveryWireScopes(t *testing.T) {
	out := callProtocol(t, &App{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	listed := out["result"].(map[string]any)["tools"].([]any)
	if len(listed) != 6 {
		t.Fatalf("got %d tools, want six", len(listed))
	}
	for _, value := range listed {
		tool := value.(map[string]any)
		mirror := tool["_meta"].(map[string]any)["securitySchemes"]
		if mirror == nil || !reflect.DeepEqual(tool["securitySchemes"], mirror) {
			t.Fatalf("%s: securitySchemes must match legacy metadata", tool["name"])
		}
	}
}

func TestOAuthDiscoveryPreservesNewProtocolEnvelope(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	r := httptest.NewRequest(http.MethodPost, "https://example.com/mcp", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2026-07-28")
	r.Header.Set("Mcp-Method", "tools/list")
	w := httptest.NewRecorder()
	(&App{}).Handler().ServeHTTP(w, r)
	var response struct {
		Result struct {
			ResultType string                     `json:"resultType"`
			Meta       map[string]json.RawMessage `json:"_meta"`
			Tools      []struct {
				SecuritySchemes json.RawMessage `json:"securitySchemes"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK {
		t.Fatalf("new protocol discovery failed: %v HTTP %d %s", err, w.Code, w.Body.String())
	}
	if response.Result.ResultType != "complete" || len(response.Result.Meta["io.modelcontextprotocol/serverInfo"]) == 0 || len(response.Result.Tools) != 6 {
		t.Fatalf("adapter lost new-protocol envelope fields: %s", w.Body.String())
	}
	for _, tool := range response.Result.Tools {
		if len(tool.SecuritySchemes) == 0 {
			t.Fatal("new-protocol discovery omitted securitySchemes")
		}
	}
}

func TestOAuthDiscoveryPreservesResultAndTools(t *testing.T) {
	schemes := []map[string]any{{"type": "oauth2", "scopes": []string{"mail.read", "mail.write"}}}
	original := &mcp.ListToolsResult{
		Meta:       mcp.Meta{"sequence": uint64(18446744073709551615)},
		Cacheable:  mcp.Cacheable{TTLMs: 1234, CacheScope: "private"},
		NextCursor: "next-page",
		Tools: []*mcp.Tool{{
			Name: "numeric_fixture", Title: "Fixture title", Description: "Fixture description",
			Meta:         mcp.Meta{"securitySchemes": schemes, "extra": json.RawMessage(`{"number":9007199254740993}`)},
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer","maximum":18446744073709551615}}}`),
			OutputSchema: json.RawMessage(`{"type":"integer","enum":[9007199254740993]}`),
			Annotations:  &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: ptr(false)},
		}, {
			Name: "no_extension", InputSchema: json.RawMessage(`{"type":"object"}`),
		}, nil},
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	handler := oauthDiscoveryMiddleware(func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return original, nil
	})
	adapted, err := handler(context.Background(), "tools/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(adapted)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]json.RawMessage
	if err := json.Unmarshal(before, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	var wantTools, gotTools []map[string]json.RawMessage
	if err := json.Unmarshal(want["tools"], &wantTools); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got["tools"], &gotTools); err != nil {
		t.Fatal(err)
	}
	expectedSchemes, err := json.Marshal(schemes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotTools[0]["securitySchemes"], expectedSchemes) {
		t.Fatalf("incorrect top-level securitySchemes: %s", gotTools[0]["securitySchemes"])
	}
	delete(gotTools[0], "securitySchemes")
	if !reflect.DeepEqual(gotTools, wantTools) {
		t.Fatalf("adapter changed original tool fields:\ngot %s\nwant %s", encoded, before)
	}
	delete(got, "tools")
	delete(want, "tools")
	if !reflect.DeepEqual(got, want) {
		t.Fatal("adapter changed result metadata, pagination or cache hints")
	}
	after, err := json.Marshal(original)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("adapter mutated the original result")
	}
	// Multiple stateless requests may share the immutable registered tools.
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			result, err := handler(context.Background(), "tools/list", nil)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := json.Marshal(result); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
}

func TestOAuthDiscoveryMiddlewarePassthrough(t *testing.T) {
	sentinel := errors.New("fixture error")
	tests := []struct {
		name, method string
		result       mcp.Result
		err          error
	}{
		{"different method", "tools/call", &mcp.CallToolResult{}, nil},
		{"handler error", "tools/list", nil, sentinel},
		{"unexpected result", "tools/list", &mcp.CallToolResult{}, nil},
		{"nil result", "tools/list", nil, nil},
		{"typed nil", "tools/list", (*mcp.ListToolsResult)(nil), nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := 0
			handler := oauthDiscoveryMiddleware(func(context.Context, string, mcp.Request) (mcp.Result, error) {
				called++
				return test.result, test.err
			})
			result, err := handler(context.Background(), test.method, nil)
			if result != test.result || err != test.err || called != 1 {
				t.Fatal("adapter altered unrelated result or error")
			}
		})
	}
}

func TestOAuthDiscoveryWireKeepsLargeSchemaNumbers(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{
		Name:        "fixture",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer","maximum":18446744073709551615}}}`),
		Meta:        mcp.Meta{"securitySchemes": []map[string]any{{"type": "oauth2", "scopes": []string{"mail.read"}}}},
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("tool was invoked during discovery")
		return nil, nil
	})
	installOAuthDiscovery(server)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	r := httptest.NewRequest("POST", "https://example.com/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"maximum":18446744073709551615`)) || bytes.Count(w.Body.Bytes(), []byte(`"securitySchemes"`)) != 2 {
		t.Fatalf("wire discovery altered schema or omitted OAuth extension: HTTP %d %s", w.Code, w.Body.String())
	}
}
