package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const (
	anonymousSessionLimit     = 60
	browserSessionLimit       = 180
	authorizationSessionLimit = 60
	tokenGrantLimit           = 120
)

// Rate identities come only from server-created state after its bearer proof
// has been checked. Client IDs, cookie-shaped input and forwarding headers are
// public/forgeable and must never select a privileged quota or create rate keys.
// Anonymous state creation has one fixed global budget, bounding the number of
// anonymous sessions and their associated counters across stateless instances.
func allowRate(ctx context.Context, store Store, bucket string, limit int) error {
	allowed, err := store.Allow(ctx, bucket, limit, time.Minute)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrRateLimited
	}
	return nil
}

func tokenRateBucket(grantID string) string { return "token:grant:" + grantID }

func (b *Browser) allowSession(ctx context.Context, token string) error {
	return allowRate(ctx, b.server.store, "browser:session:"+token, browserSessionLimit)
}

func browserStateError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrRateLimited) {
		w.Header().Set("Retry-After", "60")
		browserError(w, http.StatusTooManyRequests, "Too many requests. Please try again later.")
		return
	}
	browserError(w, http.StatusServiceUnavailable, "Authentication state unavailable.")
}
