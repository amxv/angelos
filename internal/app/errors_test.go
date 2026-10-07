package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/amxv/angelos/internal/auth"
	"github.com/amxv/angelos/internal/mail"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestErrorPayloadClassification(t *testing.T) {
	tests := []struct {
		err          error
		code, action string
	}{
		{auth.ErrInsufficientScope, "insufficient_scope", "reauthorize"},
		{deploymentDisabledError("disabled"), "deployment_disabled", "contact_operator"},
		{invalidArgumentsError(errors.New("bad field")), "invalid_arguments", "correct_input"},
		{mail.ErrInvalidInput, "invalid_arguments", "correct_input"},
		{mail.ErrStaleReference, "stale_reference", "refresh_reference"},
		{mail.ErrConflict, "conflict", "refresh_reference"},
		{mail.ErrNotFound, "not_found", "refresh_reference"},
		{mail.ErrUnsupported, "unsupported_operation", "check_capabilities"},
		{mail.ErrAutomaticSent, "unsupported_operation", "check_capabilities"},
		{mail.ErrGmailDelete, "unsupported_operation", "check_capabilities"},
		{mail.ErrLimit, "safety_limit", "narrow_request"},
		{mail.ErrUnavailable, "service_unavailable", "check_service"},
		{mail.ErrOutcomeUnknown, "outcome_unknown", "verify_outcome"},
		{context.DeadlineExceeded, "deadline_exceeded", "check_outcome"},
		{context.Canceled, "canceled", "check_outcome"},
		{errors.New("unexpected backend failure"), "operation_failed", "inspect_error"},
		// Text resembling a known error must not gain sentinel semantics.
		{errors.New(mail.ErrOutcomeUnknown.Error()), "operation_failed", "inspect_error"},
	}
	for _, test := range tests {
		for _, readOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t/%s", test.code, readOnly, test.err), func(t *testing.T) {
				err := fmt.Errorf("wrapped: %w", test.err)
				outcome := result{"status": "partial"}
				p := errorPayload(err, outcome, readOnly)
				if p["error_code"] != test.code || p["error"] != err.Error() || p["retry_safe"] != readOnly || !reflect.DeepEqual(p["outcome"], outcome) || p["recovery"] == "" {
					t.Fatalf("incorrect envelope: %#v", p)
				}
				retry := p["retry"].(result)
				if retry["action"] != test.action || retry["transport_retry_safe"] != (readOnly && !errors.Is(err, mail.ErrOutcomeUnknown)) {
					t.Fatalf("incorrect retry guidance: %#v", retry)
				}
			})
		}
	}
}

func TestToolErrorTextAndStructuredAgree(t *testing.T) {
	r := toolError(mail.ErrConflict, result{"status": "not_applied"}, false)
	if !r.IsError {
		t.Fatal("missing isError")
	}
	var text map[string]any
	if err := json.Unmarshal([]byte(r.Content[0].(*mcp.TextContent).Text), &text); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var structured map[string]any
	if err := json.Unmarshal(data, &structured); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(text, structured) {
		t.Fatalf("text and structured disagree: %#v %#v", text, structured)
	}
}

type errorBackend struct {
	*groupedBackend
	err error
}

func (b *errorBackend) Read(context.Context, mail.Reference) (mail.Message, error) {
	b.called("read")
	return mail.Message{}, b.err
}
func (b *errorBackend) SetFlags(context.Context, mail.FlagRequest) (mail.FlagResult, error) {
	b.called("flags")
	return mail.FlagResult{}, b.err
}

func TestApplicationErrorsOverSignedMCP(t *testing.T) {
	fixture := newGroupedAuthFixture(t)
	tests := []struct {
		name, scope, tool, args, code string
		writes                        bool
		err                           error
		wantCalls                     int
	}{
		{"scope", "mail.read", "mail_modify", `{"action":"flags","reference":` + groupedReferenceJSON + `,"operation":"add","flags":["\\Seen"]}`, "insufficient_scope", true, nil, 0},
		{"write_gate", "mail.read mail.write", "mail_modify", `{"action":"flags","reference":` + groupedReferenceJSON + `,"operation":"add","flags":["\\Seen"]}`, "deployment_disabled", false, nil, 0},
		{"send_gate", "mail.read mail.send", "mail_send_confirmed", `{"prepared_id":"id","confirmed_digest":"digest","append_sent":false}`, "deployment_disabled", false, nil, 0},
		{"action_validation", "mail.read", "mail_query", `{"action":"read"}`, "invalid_arguments", false, nil, 0},
		{"stale", "mail.read", "mail_query", `{"action":"read","reference":` + groupedReferenceJSON + `}`, "stale_reference", false, fmt.Errorf("wrapped: %w", mail.ErrStaleReference), 1},
		{"unknown_mutation", "mail.read mail.write", "mail_modify", `{"action":"flags","reference":` + groupedReferenceJSON + `,"operation":"add","flags":["\\Seen"]}`, "outcome_unknown", true, mail.ErrOutcomeUnknown, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &errorBackend{newGroupedBackend(), test.err}
			a := &App{Mail: backend, EnableWrites: test.writes}
			status, response := fixture.call(t, a, test.scope, test.tool, test.args)
			if status != http.StatusOK || response["error"] != nil {
				t.Fatalf("protocol error: %d %#v", status, response)
			}
			r, ok := response["result"].(map[string]any)
			if !ok || r["isError"] != true {
				t.Fatalf("expected tool error: %#v", response)
			}
			p, ok := r["structuredContent"].(map[string]any)
			if !ok || p["error_code"] != test.code {
				t.Fatalf("missing structured code %s: %#v", test.code, r)
			}
			if len(backend.calls) != test.wantCalls {
				t.Fatalf("unexpected backend calls: %v", backend.calls)
			}
			if test.tool != "mail_query" && p["retry"].(map[string]any)["transport_retry_safe"] != false {
				t.Fatalf("unsafe mutation retry: %#v", p)
			}
			if test.name == "scope" {
				if p["required_scope"] != "mail.write" || r["_meta"].(map[string]any)["mcp/www_authenticate"] == nil {
					t.Fatalf("lost scope challenge: %#v", r)
				}
				if r["content"].([]any)[0].(map[string]any)["text"] != auth.ErrInsufficientScope.Error() {
					t.Fatalf("legacy scope text changed: %#v", r)
				}
			}
		})
	}
}

// SDK-owned schema failures need not use the application envelope. They must
// still reject the request before entering the backend.
func TestSDKValidationRemainsOutsideErrorEnvelope(t *testing.T) {
	fixture := newGroupedAuthFixture(t)
	backend := newGroupedBackend()
	status, response := fixture.call(t, &App{Mail: backend}, "mail.read", "mail_query", `{"action":"not_an_action"}`)
	groupedExpectError(t, status, response)
	if len(backend.calls) != 0 {
		t.Fatalf("invalid schema entered backend: %v", backend.calls)
	}
}
