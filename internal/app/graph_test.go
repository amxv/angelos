package app

import (
	"context"
	"github.com/amxv/angelos/internal/compose"
	"github.com/amxv/angelos/internal/config"
	"github.com/amxv/angelos/internal/mail"
	"strings"
	"testing"
	"time"
)

func TestGraphPreparedSendClaimBinding(t *testing.T) {
	a := &App{Config: config.Config{Provider: "microsoft", From: "person@example.com"}}
	p, e := a.compose(compose.Input{To: []string{"to@example.com"}, Bcc: []string{"blind@example.com"}, Text: "body"})
	if e != nil || p.Transport != "microsoft_graph" || !strings.Contains(string(p.Raw), "Bcc:") {
		t.Fatal(p, e)
	}
	store := &memoryStore{}
	store.Put(context.Background(), p, "")
	sender := &fakeSender{status: "unknown"}
	a.Store = store
	a.Submitter = sender
	in := sendInput{PreparedID: p.ID, ConfirmedDigest: p.Digest}
	if _, e = a.send(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	if _, e = a.send(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	if sender.calls != 1 || store.record.Status != "unknown" {
		t.Fatal("unknown result retried")
	}
}
func TestGraphSMTPPreparationCannotCrossProviders(t *testing.T) {
	p, e := compose.Build("person@example.com", compose.Input{To: []string{"to@example.com"}, Text: "body"}, strings.Repeat("a", 32), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	for _, graph := range []bool{true, false} {
		candidate := p
		c := config.Config{}
		if graph {
			c.Provider = "microsoft"
		} else {
			candidate, e = compose.ForMicrosoftGraph(candidate)
			if e != nil {
				t.Fatal(e)
			}
		}
		store := &memoryStore{}
		store.Put(context.Background(), candidate, "")
		sender := &fakeSender{}
		a := &App{Config: c, Store: store, Submitter: sender}
		if _, e := a.send(context.Background(), sendInput{PreparedID: candidate.ID, ConfirmedDigest: candidate.Digest}); e == nil || sender.calls != 0 || !store.claimed {
			t.Fatal("cross-provider send allowed")
		}
	}
}
func TestGraphSummaryKeepsOpaqueReference(t *testing.T) {
	ref := mail.Reference{Provider: "microsoft_graph", Account: "owner", Folder: "folder", ID: "opaque"}
	page := mail.SearchResult{Provider: "microsoft_graph", Messages: []mail.Summary{{Reference: ref}}, Warnings: []string{"no snapshot"}}
	out := searchSummary(page, "folder")
	rows := out["messages"].([]result)
	if rows[0]["reference"] != ref {
		t.Fatal(out)
	}
	if _, ok := rows[0]["uid"]; ok {
		t.Fatal("fabricated UID")
	}
	if _, ok := out["uid_validity"]; ok {
		t.Fatal("fabricated UIDVALIDITY")
	}
}
