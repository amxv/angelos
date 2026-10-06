package mail

import "testing"

// BackendForCompositionTesting exports a fully local TLS/IMAP fixture only to
// the external integration test package. No raw-source production API is added.
func BackendForCompositionTesting(t *testing.T, raw string) (*Backend, func() string) {
	t.Helper()
	trace := &imapTrace{}
	backend := backendForTest(t, imapFixture(raw, "", trace), true)
	return backend, trace.String
}
