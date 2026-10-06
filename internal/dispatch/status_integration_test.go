package dispatch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/compose"
)

var statusOwner = strings.Repeat("c", 64)

func statusPreparation(t *testing.T, r *Redis, now time.Time) compose.Prepared {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	p, err := compose.Build("sender@example.com", compose.Input{
		To: []string{"to-canary@example.com"}, Bcc: []string{"bcc-canary@example.com"},
		Subject: "SUBJECT_CANARY", Text: "BODY_CANARY", HTML: "<p>HTML_CANARY</p>",
	}, hex.EncodeToString(id[:]), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Put(context.Background(), p, statusOwner); err != nil {
		t.Fatal(err)
	}
	k, _ := key(p.ID)
	t.Cleanup(func() { _, _ = r.command(context.Background(), "DEL", k) })
	return p
}

func redisValue(t *testing.T, r *Redis, command, id string) string {
	t.Helper()
	k, err := key(id)
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.command(context.Background(), command, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(v)
}

func assertStatusPrivate(t *testing.T, v any, p compose.Prepared) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{p.Digest, statusOwner, "SUBJECT_CANARY", "BODY_CANARY", "HTML_CANARY", "to-canary@example.com", "bcc-canary@example.com", "fixture-only", "raw", "digest", "recipients", "owner"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("status leaked %q: %s", secret, b)
		}
	}
}

func TestRedisStatusProjectionIsReadOnly(t *testing.T) {
	r := redisFixture(t)
	ctx := context.Background()
	for _, state := range []string{"prepared", "sending", "accepted", "rejected", "unknown", "expired"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now()
			created := now
			if state == "expired" {
				created = now.Add(-time.Hour)
			}
			p := statusPreparation(t, r, created)
			if state != "prepared" && state != "expired" {
				if _, claimed, err := r.Claim(ctx, p.ID, p.Digest, statusOwner, now); err != nil || !claimed {
					t.Fatalf("claim: %t %v", claimed, err)
				}
				if state != "sending" {
					if err := r.Complete(ctx, p.ID, state, "acknowledgement"); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := redisValue(t, r, "GET", p.ID)
			deadline := redisValue(t, r, "PEXPIRETIME", p.ID)
			for i := 0; i < 3; i++ {
				snapshot, err := r.Status(ctx, p.ID, statusOwner, now)
				if err != nil || snapshot.Status != state || snapshot.MessageID != p.MessageID || snapshot.ExpiresAt == nil || snapshot.ExpiresAt.Unix() != p.ExpiresAt.Unix() {
					t.Fatalf("status: %+v %v", snapshot, err)
				}
				if state == "accepted" || state == "rejected" || state == "unknown" {
					if snapshot.Stage != "acknowledgement" {
						t.Fatal("missing bounded stage")
					}
				} else if snapshot.Stage != "" {
					t.Fatal("invented stage")
				}
				assertStatusPrivate(t, snapshot, p)
			}
			if after := redisValue(t, r, "GET", p.ID); after != before {
				t.Fatal("status mutated record")
			}
			if after := redisValue(t, r, "PEXPIRETIME", p.ID); after != deadline {
				t.Fatal("status changed retention deadline")
			}
			if state == "prepared" {
				record, claimed, err := r.Claim(ctx, p.ID, p.Digest, statusOwner, now)
				if err != nil || !claimed || string(record.Message.Raw) != string(p.Raw) {
					t.Fatal("status consumed or changed prepared payload", err)
				}
			}
		})
	}
}

func TestRedisStatusOwnerIsolationAndLegacyMigration(t *testing.T) {
	r := redisFixture(t)
	ctx := context.Background()
	now := time.Now()
	p := statusPreparation(t, r, now)
	foreign := strings.Repeat("d", 64)
	unavailable := SendStatus{Status: "unavailable"}
	for _, owner := range []string{"", foreign} {
		snapshot, err := r.Status(ctx, p.ID, owner, now)
		if err != nil || snapshot != unavailable {
			t.Fatalf("foreign owner sees record: %+v %v", snapshot, err)
		}
		if _, claimed, err := r.Claim(ctx, p.ID, p.Digest, owner, now); err == nil || claimed {
			t.Fatal("foreign owner claimed preparation")
		}
	}
	missing := statusPreparation(t, r, now)
	k, _ := key(missing.ID)
	// Force true Redis expiry, rather than merely passing a future read clock.
	if _, err := r.command(ctx, "PEXPIREAT", k, strconv.FormatInt(now.Add(-time.Second).UnixMilli(), 10)); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := r.Status(ctx, missing.ID, statusOwner, now); err != nil || snapshot != unavailable {
		t.Fatal("expired Redis key differs from unavailable", snapshot, err)
	}
	legacy := statusPreparation(t, r, now)
	k, _ = key(legacy.ID)
	raw, _ := json.Marshal(Record{Message: legacy, Status: "prepared", ExpiresUnix: legacy.ExpiresAt.Unix()})
	if _, err := r.command(ctx, "SET", k, string(raw), "EX", 900); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := r.Status(ctx, legacy.ID, statusOwner, now); err != nil || snapshot != unavailable {
		t.Fatal("legacy receipt exposed", snapshot, err)
	}
	// An upgrade does not strand a previously approved, exact-ID/digest send.
	if _, claimed, err := r.Claim(ctx, legacy.ID, legacy.Digest, foreign, now); err != nil || !claimed {
		t.Fatal("legacy send compatibility lost", claimed, err)
	}
	if err := r.Complete(ctx, legacy.ID, "unknown", "acknowledgement"); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := r.Status(ctx, legacy.ID, foreign, now); err != nil || snapshot != unavailable {
		t.Fatal("claim assigned legacy ownership", snapshot, err)
	}
	if _, claimed, err := r.Claim(ctx, p.ID, p.Digest, statusOwner, now); err != nil || !claimed {
		t.Fatal("correct owner cannot claim", err)
	}
	if err := r.Complete(ctx, p.ID, "accepted", "acknowledgement"); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := r.Status(ctx, p.ID, statusOwner, now); err != nil || snapshot.Status != "accepted" {
		t.Fatal("completion lost ownership", snapshot, err)
	}
	if snapshot, err := r.Status(ctx, p.ID, foreign, now); err != nil || snapshot != unavailable {
		t.Fatal("completed receipt exposed to foreign owner", snapshot, err)
	}
	if _, claimed, err := r.Claim(ctx, p.ID, p.Digest, foreign, now); err == nil || claimed {
		t.Fatal("consumed claim leaked across owners")
	}
}

func TestRedisConcurrentClaimsAndStatus(t *testing.T) {
	r := redisFixture(t)
	p := statusPreparation(t, r, time.Now())
	ctx := context.Background()
	var wg sync.WaitGroup
	var claims atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, claimed, err := r.Claim(ctx, p.ID, p.Digest, statusOwner, time.Now())
			if err != nil {
				t.Error(err)
			} else if claimed {
				claims.Add(1)
				if err := r.Complete(ctx, p.ID, "unknown", "acknowledgement"); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				snapshot, err := r.Status(ctx, p.ID, statusOwner, time.Now())
				if err != nil {
					t.Error(err)
					return
				}
				switch snapshot.Status {
				case "prepared", "sending", "unknown":
				default:
					t.Errorf("incoherent status %q", snapshot.Status)
				}
				assertStatusPrivate(t, snapshot, p)
			}
		}()
	}
	wg.Wait()
	if claims.Load() != 1 {
		t.Fatalf("claimed %d times", claims.Load())
	}
	snapshot, err := r.Status(ctx, p.ID, statusOwner, time.Now())
	if err != nil || snapshot.Status != "unknown" {
		t.Fatal("final status", snapshot, err)
	}
}

func TestRedisStatusDoesNotExposeUnboundedStage(t *testing.T) {
	r := redisFixture(t)
	p := statusPreparation(t, r, time.Now())
	ctx := context.Background()
	if _, claimed, err := r.Claim(ctx, p.ID, p.Digest, statusOwner, time.Now()); err != nil || !claimed {
		t.Fatal(err)
	}
	if err := r.Complete(ctx, p.ID, "rejected", "BODY_CANARY to-canary@example.com"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.Status(ctx, p.ID, statusOwner, time.Now())
	if err != nil || snapshot.Stage != "" {
		t.Fatal("unbounded stage exposed", snapshot, err)
	}
	assertStatusPrivate(t, snapshot, p)
}
