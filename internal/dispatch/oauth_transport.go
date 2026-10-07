package dispatch

import (
	"context"
	"encoding/json"
	"errors"
)

// Command exposes the existing hardened Redis REST transport to the OAuth state
// store. OAuth uses the same HTTPS destination policy and bearer credential as
// send protection, with a smaller bounded response. Commands are never retried.
func (r *Redis) Command(ctx context.Context, args ...any) (json.RawMessage, error) {
	if r == nil || r.client == nil {
		return nil, errors.New("durable store unavailable")
	}
	raw, err := json.Marshal(args)
	if err != nil || len(raw) > 256<<10 {
		return nil, errors.New("invalid or oversized OAuth state operation")
	}
	return r.commandLimited(ctx, 1<<20, args...)
}
