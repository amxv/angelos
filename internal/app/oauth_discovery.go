package app

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// installOAuthDiscovery exposes the top-level securitySchemes extension used by
// ChatGPT, while retaining the SDK's _meta mirror for older clients. The Go SDK
// does not currently model that top-level tool field. Adapt only tools/list,
// after its normal handler, without changing tool execution or authentication.
func installOAuthDiscovery(server *mcp.Server) {
	server.AddReceivingMiddleware(oauthDiscoveryMiddleware)
}

// Embedding the original result preserves pagination, cache hints, metadata and
// protocol-version fields. The explicit Tools field shadows only its tool list.
// No schemas or other JSON values are decoded through float64, and registered
// tool objects remain immutable across concurrent requests.
type oauthDiscoveryResult struct {
	*mcp.ListToolsResult
	Tools []*oauthDiscoveryTool `json:"tools"`
}

type oauthDiscoveryTool struct {
	*mcp.Tool
	SecuritySchemes any `json:"securitySchemes,omitempty"`
}

func oauthDiscoveryMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
		result, err := next(ctx, method, request)
		if err != nil || method != "tools/list" {
			return result, err
		}
		listed, ok := result.(*mcp.ListToolsResult)
		if !ok || listed == nil {
			return result, nil
		}
		copy := *listed
		adapted := &oauthDiscoveryResult{ListToolsResult: &copy}
		if listed.Tools != nil {
			adapted.Tools = make([]*oauthDiscoveryTool, len(listed.Tools))
		}
		for i, tool := range listed.Tools {
			if tool != nil {
				adapted.Tools[i] = &oauthDiscoveryTool{Tool: tool, SecuritySchemes: tool.Meta["securitySchemes"]}
			}
		}
		return adapted, nil
	}
}
