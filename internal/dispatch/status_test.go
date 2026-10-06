package dispatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/compose"
)

func statusResponseFixture(t *testing.T, response any) *Redis {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var args []any
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			t.Error(err)
		}
		if len(args) != 6 || args[0] != "EVAL" || args[1] != statusScript || args[2] != float64(1) || args[3] != "angelos:send:"+strings.Repeat("a", 32) || args[4] != statusOwner || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Errorf("unexpected status operation: %#v", args)
		}
		json.NewEncoder(w).Encode(map[string]any{"result": response})
	}))
	t.Cleanup(s.Close)
	return &Redis{endpoint: s.URL, token: "fixture-token", client: s.Client()}
}

func TestStatusProjectionDefensiveValidation(t *testing.T) {
	expiry := strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)
	cases := []struct {
		name     string
		response any
		wantErr  bool
		stage    string
	}{
		{"valid", []string{"accepted", "<MiXeD@Example.COM>", expiry, "acknowledgement"}, false, "acknowledgement"},
		{"unavailable strips other fields", []string{"unavailable", "PRIVATE", "PRIVATE", "PRIVATE"}, false, ""},
		{"unbounded stage omitted", []string{"rejected", "<MiXeD@Example.COM>", expiry, "PRIVATE canary@example.com"}, false, ""},
		{"empty message ID allowed", []string{"sending", "", expiry, ""}, false, ""},
		{"unknown state", []string{"delivered", "<id@example.com>", expiry, ""}, true, ""},
		{"too few fields", []string{"accepted"}, true, ""},
		{"too many fields", []string{"accepted", "<id@example.com>", expiry, "", "PRIVATE"}, true, ""},
		{"wrong field type", []any{"accepted", 12, expiry, ""}, true, ""},
		{"null result", nil, true, ""},
		{"invalid id", []string{"accepted", "PRIVATE invalid id", expiry, ""}, true, ""},
		{"control id", []string{"accepted", "<id@example.com>\r\nBcc: canary@example.com", expiry, ""}, true, ""},
		{"multiple ids", []string{"accepted", "<id@example.com> <other@example.com>", expiry, ""}, true, ""},
		{"huge id", []string{"accepted", "<" + strings.Repeat("a", 1000) + "@example.com>", expiry, ""}, true, ""},
		{"negative expiry", []string{"prepared", "<id@example.com>", "-1", ""}, true, ""},
		{"zero expiry", []string{"prepared", "<id@example.com>", "0", ""}, true, ""},
		{"malformed expiry", []string{"prepared", "<id@example.com>", "PRIVATE", ""}, true, ""},
		{"unserializable expiry", []string{"prepared", "<id@example.com>", "253402300800", ""}, true, ""},
		{"overflow expiry", []string{"prepared", "<id@example.com>", "9223372036854775808", ""}, true, ""},
		{"huge response", []string{"prepared", "<id@example.com>", expiry, strings.Repeat("x", 8<<10)}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := statusResponseFixture(t, tc.response)
			status, err := r.Status(context.Background(), strings.Repeat("a", 32), statusOwner, time.Now())
			if (err != nil) != tc.wantErr {
				t.Fatalf("status=%+v err=%v; want error=%t", status, err, tc.wantErr)
			}
			if status.Stage != tc.stage {
				t.Fatal("unexpected projected stage", status.Stage)
			}
			if tc.name == "valid" && status.MessageID != "<MiXeD@Example.COM>" {
				t.Fatal("Message-ID case changed")
			}
			if tc.name == "unavailable strips other fields" && status != (SendStatus{Status: "unavailable"}) {
				t.Fatal("unavailable result exposed extra fields", status)
			}
			encoded, marshalErr := json.Marshal(status)
			if marshalErr != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "canary@example.com") || (err != nil && (strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "canary@example.com"))) {
				t.Fatal("malformed projection leaked or failed JSON serialization", err, marshalErr)
			}
		})
	}
}

func TestOwnerAndIDValidationBeforeRedis(t *testing.T) {
	r := &Redis{}
	ctx := context.Background()
	for _, owner := range []string{"", "plaintext-subject", strings.Repeat("A", 64)} {
		if err := r.Put(ctx, compose.Prepared{ID: strings.Repeat("a", 32)}, owner); err == nil {
			t.Fatal("invalid owner accepted for preparation")
		}
		if status, err := r.Status(ctx, strings.Repeat("a", 32), owner, time.Now()); err != nil || status != (SendStatus{Status: "unavailable"}) {
			t.Fatal("invalid owner queried Redis", status, err)
		}
	}
	for _, id := range []string{"", "../bad", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32)} {
		if _, err := r.Status(ctx, id, statusOwner, time.Now()); err == nil {
			t.Fatal("invalid id accepted")
		}
	}
}
