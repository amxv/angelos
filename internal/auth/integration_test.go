package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exercise the real SDK transport, rather than merely calling our middleware or
// a tool closure. This pins the critical principal-context propagation contract
// across initialize, tools/list, and independently authenticated tools/call.
func TestStatelessSDKPreservesPrincipalAndScopes(t *testing.T) {
	f := newFixture(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "auth-integration", Version: "test"}, nil)
	var authorizedCalls atomic.Int32
	mcp.AddTool[struct{}, map[string]any](server, &mcp.Tool{Name: "check_send_scope", Description: "Test verified identity propagation"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		principal, ok := PrincipalFromContext(ctx)
		if !ok || principal.Issuer != f.a.config.Issuer || principal.Resource != f.a.config.ResourceURL || principal.Subject != "owner-123" || !HasScope(ctx, ScopeRead) || PrincipalBinding(ctx) == "" {
			t.Error("SDK dropped authenticated request context")
			return nil, nil, ErrInvalidToken
		}
		if err := RequireScope(ctx, ScopeSend); err != nil {
			return nil, nil, err
		}
		authorizedCalls.Add(1)
		return nil, map[string]any{"subject": principal.Subject, "send": true}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 64 * 1024, PropagateRequestCancellation: true})
	endpoint := httptest.NewServer(f.a.Middleware(handler))
	defer endpoint.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	post := func(token, message string) (int, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint.URL, strings.NewReader(message))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body, resp.Header
	}
	full := rsaToken(t, f.key, tokenHeader(), f.claims())
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"auth-test","version":"1"}}}`
	if status, _, headers := post("", initialize); status != 401 || headers.Get("WWW-Authenticate") == "" {
		t.Fatalf("anonymous initialization status=%d challenge=%q", status, headers.Get("WWW-Authenticate"))
	}
	if status, body, headers := post(full, initialize); status != 200 || !strings.Contains(string(body), `"protocolVersion"`) || headers.Get("MCP-Session-Id") != "" {
		t.Fatalf("stateless initialization failed: %d %s", status, body)
	}
	if status, body, _ := post(full, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); status != 202 {
		t.Fatalf("initialized notification failed: %d %s", status, body)
	}
	if status, body, _ := post(full, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`); status != 200 || !strings.Contains(string(body), `check_send_scope`) {
		t.Fatalf("tool listing failed: %d %s", status, body)
	}
	toolCall := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_send_scope","arguments":{}}}`
	status, body, _ := post(full, toolCall)
	var response struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool           `json:"isError"`
			Output  map[string]any `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if status != 200 || len(response.Error) != 0 || response.Result.IsError || response.Result.Output["subject"] != "owner-123" || response.Result.Output["send"] != true || authorizedCalls.Load() != 1 {
		t.Fatalf("authorized SDK tool lost identity/scope: %d %s calls=%d", status, body, authorizedCalls.Load())
	}
	readClaims := f.claims()
	readClaims["scope"] = ScopeRead
	readOnly := rsaToken(t, f.key, tokenHeader(), readClaims)
	status, body, _ = post(readOnly, toolCall)
	if status != 200 || !strings.Contains(string(body), `"isError":true`) || authorizedCalls.Load() != 1 {
		t.Fatalf("read-only caller passed send guard: %d %s calls=%d", status, body, authorizedCalls.Load())
	}
	if status, _, _ := post("", toolCall); status != 401 || authorizedCalls.Load() != 1 {
		t.Fatalf("previous authorization leaked to anonymous request: %d calls=%d", status, authorizedCalls.Load())
	}
}
