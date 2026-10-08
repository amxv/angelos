package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedisRefreshRateIsAtomicPreservesTokenAndCannotBlockReplayRevocation(t *testing.T) {
	a, b, redis := oauthRedisFixture(t)
	ctx := context.Background()
	grant := fixtureGrant(a)
	if err := a.CreateGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateRefresh(ctx, "initial", fixtureRefresh(grant)); err != nil {
		t.Fatal(err)
	}
	bucket := tokenRateBucket(grant.ID)
	for range tokenGrantLimit {
		if err := allowRate(ctx, a, bucket, tokenGrantLimit); err != nil {
			t.Fatal(err)
		}
	}
	// All instances observe the same exhausted grant budget. None may spend the
	// refresh token, create a successor, or revoke the grant on ordinary 429s.
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := a
			if i%2 == 0 {
				store = b
			}
			_, err := store.RotateRefresh(ctx, "initial", fmt.Sprintf("next-%d", i), grant.ClientID, grant.Resource, time.Now())
			if !errors.Is(err, ErrRateLimited) {
				t.Errorf("exhausted refresh returned %v", err)
			}
		}(i)
	}
	wg.Wait()
	if _, err := a.GetGrant(ctx, grant.ID); err != nil {
		t.Fatal("rate denial revoked grant", err)
	}
	key, _ := a.stateKey("rate", bucket)
	assertRedisTTL(t, redis, key, 60)
	if _, err := redis.Command(ctx, "DEL", key); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RotateRefresh(ctx, "initial", "successor", grant.ClientID, grant.Resource, time.Now()); err != nil {
		t.Fatal("rate denial spent refresh", err)
	}
	for range tokenGrantLimit - 1 {
		if err := allowRate(ctx, a, bucket, tokenGrantLimit); err != nil {
			t.Fatal(err)
		}
	}
	// Replays must still revoke a compromised grant when its budget is full.
	if _, err := a.RotateRefresh(ctx, "initial", "replay", grant.ClientID, grant.Resource, time.Now()); !errors.Is(err, ErrReplay) {
		t.Fatal("rate cap hid refresh replay", err)
	}
	if _, err := a.GetGrant(ctx, grant.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("replay left grant live", err)
	}
}

func TestRedisRefreshInvalidProofCannotSpendVictimQuota(t *testing.T) {
	a, _, redis := oauthRedisFixture(t)
	ctx := context.Background()
	grant := fixtureGrant(a)
	if err := a.CreateGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateRefresh(ctx, "initial", fixtureRefresh(grant)); err != nil {
		t.Fatal(err)
	}
	for i := range 150 {
		if _, err := a.RotateRefresh(ctx, "initial", fmt.Sprintf("wrong-%d", i), "wrong-client", grant.Resource, time.Now()); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := a.RotateRefresh(ctx, fmt.Sprintf("unknown-%d", i), "next", grant.ClientID, grant.Resource, time.Now()); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	keys, err := redis.Command(ctx, "KEYS", a.prefix+"rate:*")
	if err != nil || string(keys) != "[]" {
		t.Fatal("unproven refresh created counters", string(keys), err)
	}
	if _, err := a.RotateRefresh(ctx, "initial", "successor", grant.ClientID, grant.Resource, time.Now()); err != nil {
		t.Fatal("invalid proof burned refresh", err)
	}
}

func TestRedisRateCorruptionAndLostResponsesFailClosed(t *testing.T) {
	for _, corrupt := range []string{"-1", "1.5", "not-a-count", "120", "persistent"} {
		t.Run(corrupt, func(t *testing.T) {
			a, _, redis := oauthRedisFixture(t)
			ctx := context.Background()
			grant := fixtureGrant(a)
			if err := a.CreateGrant(ctx, grant); err != nil {
				t.Fatal(err)
			}
			if err := a.CreateRefresh(ctx, "initial", fixtureRefresh(grant)); err != nil {
				t.Fatal(err)
			}
			key, _ := a.stateKey("rate", tokenRateBucket(grant.ID))
			value := corrupt
			args := []any{"SET", key, value, "EX", 60}
			if corrupt == "persistent" {
				args = []any{"SET", key, "1"}
			}
			if _, err := redis.Command(ctx, args...); err != nil {
				t.Fatal(err)
			}
			_, err := a.RotateRefresh(ctx, "initial", "next", grant.ClientID, grant.Resource, time.Now())
			want := ErrUnavailable
			if corrupt == "120" {
				want = ErrRateLimited
			}
			if !errors.Is(err, want) {
				t.Fatal("bad rate state accepted", err)
			}
			if _, err := redis.Command(ctx, "DEL", key); err != nil {
				t.Fatal(err)
			}
			if _, err := a.RotateRefresh(ctx, "initial", "next", grant.ClientID, grant.Resource, time.Now()); err != nil {
				t.Fatal("failed rate check mutated refresh", err)
			}
		})
	}
	a, _, redis := oauthRedisFixture(t)
	redis.loseResponse.Store(true)
	before := redis.requests.Load()
	if err := allowRate(context.Background(), a, "lost-response", 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ambiguous rate response accepted", err)
	}
	if redis.requests.Load()-before != 1 {
		t.Fatal("ambiguous rate mutation retried")
	}
	if err := allowRate(context.Background(), a, "lost-response", 1); !errors.Is(err, ErrRateLimited) {
		t.Fatal("ambiguous committed count not retained", err)
	}
}

func TestRedisAnonymousAdmissionIsBoundedAcrossInstances(t *testing.T) {
	a, b, redis := oauthRedisFixture(t)
	config := coreTestConfig(t)
	config.OwnerSubject = a.owner
	first, err := New(config, a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(config, b)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range 180 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			server := first
			if i%2 == 0 {
				server = second
			}
			r := httptest.NewRequest("GET", config.Issuer+"/oauth/login", nil)
			r.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i))
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			if w.Code == 200 {
				successes.Add(1)
			} else if w.Code != 429 {
				t.Errorf("anonymous admission returned %d: %s", w.Code, w.Body.String())
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != anonymousSessionLimit {
		t.Fatalf("anonymous admissions=%d, want %d", successes.Load(), anonymousSessionLimit)
	}
	keys, err := redis.Command(context.Background(), "KEYS", a.prefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := json.Unmarshal(keys, &names); err != nil {
		t.Fatal(err)
	}
	var sessions, counters int
	for _, key := range names {
		if strings.Contains(key, ":session:") {
			sessions++
		}
		if strings.Contains(key, ":rate:") {
			counters++
		}
	}
	if sessions != anonymousSessionLimit || counters != 1 {
		t.Fatalf("unbounded anonymous state: sessions=%d counters=%d", sessions, counters)
	}
}
