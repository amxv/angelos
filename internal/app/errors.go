package app

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/amxv/angelos/internal/auth"
	"github.com/amxv/angelos/internal/mail"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// classifiedError marks errors at their source without parsing human-readable
// backend messages. Unrecognized errors deliberately retain a generic code.
type classifiedError struct {
	cause    error
	code     string
	recovery string
	action   string
}

func (e *classifiedError) Error() string { return e.cause.Error() }
func (e *classifiedError) Unwrap() error { return e.cause }
func deploymentDisabledError(message string) error {
	return &classifiedError{errors.New(message), "deployment_disabled", "Ask the server operator to enable the required capability; do not bypass deployment gates.", "contact_operator"}
}
func invalidArgumentsError(err error) error {
	return &classifiedError{err, "invalid_arguments", "Correct the arguments using tools/list and the action's required fields, then submit a new request.", "correct_input"}
}

func classifyToolError(err error) (code, recovery, action string) {
	var classified *classifiedError
	if errors.As(err, &classified) {
		return classified.code, classified.recovery, classified.action
	}
	switch {
	case errors.Is(err, mail.ErrOutcomeUnknown):
		return "outcome_unknown", "Inspect the affected mailbox and outcome before any new mutation. For sending, inspect send_status and Sent; never automatically resend or prepare a duplicate.", "verify_outcome"
	case errors.Is(err, auth.ErrInsufficientScope):
		return "insufficient_scope", "Obtain authorization for the required scope, then submit a new request.", "reauthorize"
	case errors.Is(err, mail.ErrInvalidInput):
		return "invalid_arguments", "Correct the request using tools/list and valid exact references before submitting a new request.", "correct_input"
	case errors.Is(err, mail.ErrStaleReference):
		return "stale_reference", "Search the mailbox again and use its current folder, UIDVALIDITY and UID; discard old cursors and references.", "refresh_reference"
	case errors.Is(err, mail.ErrDraftChanged):
		return "conflict", "Read the complete draft again and review its new source_digest before revising or preparing. The original was not changed by this operation.", "refresh_reference"
	case errors.Is(err, mail.ErrConflict):
		return "conflict", "Read the message again and review current flags and MODSEQ before deciding whether to submit a new change.", "refresh_reference"
	case errors.Is(err, mail.ErrNotFound):
		return "not_found", "Search again to establish whether the message moved or disappeared; use a newly verified reference.", "refresh_reference"
	case errors.Is(err, mail.ErrGmailDelete), errors.Is(err, mail.ErrAutomaticSent), errors.Is(err, mail.ErrUnsupported):
		return "unsupported_operation", "Check mail_query capabilities and provider restrictions; choose a supported operation without weakening safety requirements.", "check_capabilities"
	case errors.Is(err, mail.ErrLimit):
		return "safety_limit", "Narrow the request or use smaller bounded pages. Inspect any partial outcome before further changes.", "narrow_request"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded", "A read-only request may be repeated after waiting. For mutations or sending, inspect the outcome first; a timeout does not prove failure.", "check_outcome"
	case errors.Is(err, context.Canceled):
		return "canceled", "Continue only if the request is still wanted. Verify mutation or send outcomes before any new action.", "check_outcome"
	case errors.Is(err, mail.ErrUnavailable):
		return "service_unavailable", "Check service connectivity and account authentication. Retry reads only after checking; verify mutation and send outcomes first.", "check_service"
	default:
		return "operation_failed", "Inspect the error and any partial outcome. Verify mutations before further action; never automatically resend or create a duplicate preparation after an uncertain send.", "inspect_error"
	}
}

// toolError covers errors reaching the application handler. SDK schema and
// protocol validation can reject a call before this handler is entered.
func errorPayload(err error, outcome any, readOnly bool) result {
	code, recovery, action := classifyToolError(err)
	// retry_safe is the legacy read-only hint, not permission to retry after
	// changing inputs or to ignore an unknown outcome. The explicit transport
	// field is conservative even if an unknown-outcome error reaches a read tool.
	transportSafe := readOnly && !errors.Is(err, mail.ErrOutcomeUnknown)
	payload := result{
		"error": err.Error(), "outcome": outcome, "retry_safe": readOnly,
		"error_code": code, "recovery": recovery,
		"retry": result{"transport_retry_safe": transportSafe, "action": action},
	}
	return payload
}

func toolError(err error, outcome any, readOnly bool) *mcp.CallToolResult {
	payload := errorPayload(err, outcome, readOnly)
	b, _ := json.Marshal(payload)
	return &mcp.CallToolResult{IsError: true, StructuredContent: payload, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}
