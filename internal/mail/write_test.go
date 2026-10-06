package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amxv/angelos/internal/config"
	"github.com/emersion/go-imap/v2"
)

type writeStep struct {
	contains   string
	exact      string
	reply      string // {tag} is replaced with the received command tag.
	literal    string
	disconnect bool
}

// Every command is checked. An accidental EXPUNGE, CLOSE, sequence-number
// STORE, or unsupported MOVE fallback fails a test, even on connection cleanup.
// The fake server uses TLS over net.Pipe; no live mailbox or listener is used.
func writeTestBackend(t *testing.T, caps string, steps []writeStep) *Backend {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certSpec := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.test"}, DNSNames: []string{"mail.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, certSpec, certSpec, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	done := make(chan error, 1)
	var once sync.Once
	b := &Backend{config: config.Config{Username: "owner", Password: "test-password", IMAP: config.Endpoint{Host: "mail.test", Port: 993, TLSMode: "tls"}, Timeout: 5 * time.Second}, roots: roots}
	b.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var c net.Conn
		once.Do(func() {
			clientSide, serverSide := net.Pipe()
			c = clientSide
			go func() {
				conn := tls.Server(serverSide, serverTLS)
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				err := runWriteScript(conn, caps, steps)
				done <- err
			}()
		})
		if c == nil {
			return nil, errors.New("unexpected second mailbox connection")
		}
		return c, nil
	}
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("IMAP test did not complete")
		}
	})
	return b
}

func runWriteScript(conn net.Conn, caps string, steps []writeStep) error {
	if _, err := fmt.Fprintf(conn, "* OK [CAPABILITY %s] fake ready\r\n", caps); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	index := 0
	loggedIn := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if index != len(steps) {
				return fmt.Errorf("connection ended after %d of %d expected commands: %w", index, len(steps), err)
			}
			return nil
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		tag, command, ok := strings.Cut(line, " ")
		if !ok {
			return fmt.Errorf("invalid command %q", line)
		}
		if strings.HasPrefix(command, "LOGIN ") {
			if loggedIn {
				return errors.New("duplicate LOGIN")
			}
			loggedIn = true
			if _, err := fmt.Fprintf(conn, "%s OK [CAPABILITY %s] logged in\r\n", tag, caps); err != nil {
				return err
			}
			continue
		}
		if command == "CAPABILITY" {
			if _, err := fmt.Fprintf(conn, "* CAPABILITY %s\r\n%s OK capabilities\r\n", caps, tag); err != nil {
				return err
			}
			continue
		}
		if command == "EXPUNGE" || command == "CLOSE" || strings.HasPrefix(command, "STORE ") || strings.HasPrefix(command, "MOVE ") || strings.HasPrefix(command, "COPY ") {
			return fmt.Errorf("unsafe command: %s", command)
		}
		if index >= len(steps) {
			return fmt.Errorf("unexpected command: %s", command)
		}
		step := steps[index]
		index++
		if step.exact != "" && command != step.exact {
			return fmt.Errorf("command %d: got %q, want %q", index, command, step.exact)
		}
		if !strings.Contains(command, step.contains) {
			return fmt.Errorf("command %d: got %q, want substring %q", index, command, step.contains)
		}
		if step.disconnect {
			return nil
		}
		if step.literal != "" {
			marker := "{" + strconv.Itoa(len(step.literal)) + "}"
			if !strings.HasSuffix(command, marker) {
				return fmt.Errorf("wrong APPEND literal size in %q", command)
			}
			if _, err := io.WriteString(conn, "+ send literal\r\n"); err != nil {
				return err
			}
			data := make([]byte, len(step.literal)+2)
			if _, err := io.ReadFull(r, data); err != nil {
				return err
			}
			if string(data) != step.literal+"\r\n" {
				return errors.New("APPEND literal differed from original message")
			}
		}
		if _, err := io.WriteString(conn, strings.ReplaceAll(step.reply, "{tag}", tag)); err != nil {
			return err
		}
	}
}

func selectWriteStep(validity uint32, condstore bool) writeStep {
	extra := ""
	if condstore {
		extra = "* OK [HIGHESTMODSEQ 12] modseq\r\n"
	}
	return writeStep{contains: "SELECT ", reply: fmt.Sprintf("* 8 EXISTS\r\n* FLAGS (\\Seen \\Answered \\Flagged \\Draft \\Deleted)\r\n* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Draft \\Deleted \\*)] permanent\r\n* OK [UIDVALIDITY %d] validity\r\n* OK [UIDNEXT 30] next\r\n%s{tag} OK [READ-WRITE] selected\r\n", validity, extra)}
}

func fetchFlagStep(flags string, modseq uint64) writeStep {
	extra := ""
	if modseq != 0 {
		extra = fmt.Sprintf(" MODSEQ (%d)", modseq)
	}
	return writeStep{contains: "UID FETCH 17 ", reply: fmt.Sprintf("* 4 FETCH (UID 17 FLAGS (%s)%s)\r\n{tag} OK fetched\r\n", flags, extra)}
}

func testWriteRef() Reference { return Reference{Folder: "INBOX", UIDValidity: 9, UID: 17} }

func TestWriteInputValidation(t *testing.T) {
	valid := FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`, "$Junk", "Project-A"}}
	flags, _, err := parseFlagRequest(valid)
	if err != nil || len(flags) != 3 {
		t.Fatalf("valid request rejected: %v", err)
	}
	for _, bad := range []string{`\Deleted`, `\Recent`, `\*`, "bad flag", "bad)flag", "bad\r\nflag", "étiquette", ""} {
		req := valid
		req.Flags = []string{bad}
		if _, _, err := parseFlagRequest(req); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("accepted flag %q", bad)
		}
	}
	req := valid
	req.Operation = "set"
	if _, _, err := parseFlagRequest(req); err == nil {
		t.Error("allowed wholesale flag replacement")
	}
	for _, ref := range []Reference{{Folder: "INBOX", UID: 17}, {Folder: "INBOX", UIDValidity: 9}, {Folder: "INBOX\r\nEXPUNGE", UIDValidity: 9, UID: 17}} {
		req := valid
		req.Reference = ref
		if _, _, err := parseFlagRequest(req); err == nil {
			t.Errorf("accepted incomplete reference %+v", ref)
		}
	}
}

func TestSingleUIDDoesNotExpandRanges(t *testing.T) {
	for _, set := range []imap.NumSet{imap.UIDSet{{Start: 1, Stop: ^imap.UID(0)}}, imap.UIDSetNum(0), imap.SeqSetNum(17), imap.UIDSetNum(17, 18)} {
		if _, ok := singleUID(set); ok {
			t.Errorf("accepted non-single UID %v", set)
		}
	}
	if uid, ok := singleUID(imap.UIDSetNum(17)); !ok || uid != 17 {
		t.Fatal("rejected exact UID")
	}
}

func TestCapabilitiesAndSpecialUse(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS MOVE CONDSTORE SPECIAL-USE", []writeStep{{contains: "LIST ", reply: "* LIST (\\Trash) \"/\" \"Deleted Messages\"\r\n* LIST (\\Sent) \"/\" \"Sent Items\"\r\n* LIST (\\Drafts) \"/\" \"Draft Mail\"\r\n* LIST (\\Noselect \\Trash) \"/\" \"Parent\"\r\n{tag} OK listed\r\n"}})
	got, err := b.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Move || !got.UIDExpunge || !got.CondStore || !got.SpecialUse || len(got.SpecialFolders["trash"]) != 1 || got.SpecialFolders["trash"][0] != "Deleted Messages" {
		t.Fatalf("wrong capabilities: %+v", got)
	}
}

func TestSetFlagsUsesConditionalUIDStore(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 CONDSTORE", []writeStep{selectWriteStep(9, true), fetchFlagStep("", 12), {contains: `UID STORE 17 (UNCHANGEDSINCE 12) +FLAGS (\Seen)`, reply: "* 4 FETCH (UID 17 FLAGS (\\Seen) MODSEQ (13))\r\n{tag} OK stored\r\n"}})
	got, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Conditional || got.ModSeq != 13 || len(got.Flags) != 1 {
		t.Fatalf("wrong flags result: %+v", got)
	}
}

func TestSetFlagsReportsConcurrentModification(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 CONDSTORE", []writeStep{selectWriteStep(9, true), fetchFlagStep("", 12), {contains: `UID STORE 17 (UNCHANGEDSINCE 12) +FLAGS (\Seen)`, reply: "{tag} OK [MODIFIED 17] another client changed it\r\n"}})
	_, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want conflict", err)
	}
}

func TestConditionalConflictWithMatchingUnsolicitedFlags(t *testing.T) {
	// RFC 7162 permits this FETCH even though the STORE failed its guard.
	b := writeTestBackend(t, "IMAP4rev1 CONDSTORE", []writeStep{selectWriteStep(9, true), fetchFlagStep("", 12), {contains: `UID STORE 17 (UNCHANGEDSINCE 12) +FLAGS (\Seen)`, reply: "* 4 FETCH (UID 17 FLAGS (\\Seen) MODSEQ (13))\r\n{tag} OK [MODIFIED 17] another client changed it\r\n"}})
	_, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want conflict despite matching FETCH", err)
	}
}

func TestModifiedTrackerHandlesChunkBoundariesWithoutKeepingPayload(t *testing.T) {
	tracker := &modifiedResponseTracker{}
	for _, part := range []string{"T2 OK [mo", "di", "fied 17] concurrent update\r\n"} {
		tracker.observe([]byte(part))
	}
	if !tracker.seen() {
		t.Fatal("split MODIFIED marker missed")
	}
	tracker.reset()
	tracker.observe([]byte("T3 OK stored\r\n"))
	if tracker.seen() {
		t.Fatal("previous response leaked into next command")
	}
	tracker.observe([]byte("[[MODIFIED"))
	if !tracker.seen() {
		t.Fatal("overlapping prefix missed")
	}
}

func TestSetFlagsRejectsStaleModSeqBeforeMutation(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 CONDSTORE", []writeStep{selectWriteStep(9, true), fetchFlagStep("", 13)})
	_, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`}, UnchangedSince: 12})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want conflict", err)
	}
}

func TestSetFlagsWithoutCondstoreUsesDelta(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1", []writeStep{selectWriteStep(9, false), fetchFlagStep(`\Seen \Flagged`, 0), {contains: `UID STORE 17 -FLAGS (\Seen)`, reply: "* 4 FETCH (UID 17 FLAGS (\\Flagged))\r\n{tag} OK stored\r\n"}})
	got, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "remove", Flags: []string{`\Seen`}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Conditional || len(got.Warnings) == 0 || len(got.Flags) != 1 || got.Flags[0] != `\Flagged` {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestExplicitCondstorePreconditionNeverIgnored(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1", []writeStep{selectWriteStep(9, false)})
	_, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`}, UnchangedSince: 12})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v, want unsupported", err)
	}
}

func TestAllMessageMutationsRejectUIDValidityChange(t *testing.T) {
	for name, run := range map[string]func(*Backend) error{
		"flags": func(b *Backend) error {
			_, err := b.SetFlags(context.Background(), FlagRequest{Reference: testWriteRef(), Operation: "add", Flags: []string{`\Seen`}})
			return err
		},
		"copy":   func(b *Backend) error { _, err := b.Copy(context.Background(), testWriteRef(), "Archive"); return err },
		"move":   func(b *Backend) error { _, err := b.Move(context.Background(), testWriteRef(), "Archive"); return err },
		"delete": func(b *Backend) error { _, err := b.Delete(context.Background(), testWriteRef()); return err },
	} {
		t.Run(name, func(t *testing.T) {
			b := writeTestBackend(t, "IMAP4rev1 MOVE UIDPLUS", []writeStep{selectWriteStep(10, false)})
			if err := run(b); !errors.Is(err, ErrStaleReference) {
				t.Fatalf("got %v, want stale reference", err)
			}
		})
	}
}

func TestMoveAndDeleteFailClosedWithoutCapability(t *testing.T) {
	for name, run := range map[string]func(*Backend) error{
		"move":   func(b *Backend) error { _, err := b.Move(context.Background(), testWriteRef(), "Archive"); return err },
		"trash":  func(b *Backend) error { _, err := b.Trash(context.Background(), testWriteRef()); return err },
		"delete": func(b *Backend) error { _, err := b.Delete(context.Background(), testWriteRef()); return err },
	} {
		t.Run(name, func(t *testing.T) {
			b := writeTestBackend(t, "IMAP4rev1", nil)
			if err := run(b); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("got %v, want unsupported", err)
			}
		})
	}
}

func TestCopyReturnsDestinationIdentity(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS", []writeStep{selectWriteStep(9, false), fetchFlagStep("", 0), {contains: `UID COPY 17 "Archive"`, reply: "{tag} OK [COPYUID 22 17 58] copied\r\n"}})
	got, err := b.Copy(context.Background(), testWriteRef(), "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "copied" || got.Destination == nil || *got.Destination != (Reference{Folder: "Archive", UIDValidity: 22, UID: 58}) {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestMoveUsesOnlyNativeUIDMove(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 MOVE UIDPLUS", []writeStep{selectWriteStep(9, false), fetchFlagStep("", 0), {contains: `UID MOVE 17 "Archive"`, reply: "* OK [COPYUID 22 17 58] copied\r\n* 4 EXPUNGE\r\n{tag} OK moved\r\n"}})
	got, err := b.Move(context.Background(), testWriteRef(), "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "moved" || got.Destination == nil || got.Destination.UID != 58 {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestMissingMessageCannotBeCopied(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1", []writeStep{selectWriteStep(9, false), {contains: "UID FETCH 17 ", reply: "{tag} OK no matching UID\r\n"}})
	_, err := b.Copy(context.Background(), testWriteRef(), "Archive")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want not found", err)
	}
}

func TestTrashRefusesMissingOrAmbiguousSpecialUse(t *testing.T) {
	for name, listing := range map[string]string{"missing": "* LIST () \"/\" \"Trash\"\r\n", "ambiguous": "* LIST (\\Trash) \"/\" \"Bin A\"\r\n* LIST (\\Trash) \"/\" \"Bin B\"\r\n"} {
		t.Run(name, func(t *testing.T) {
			b := writeTestBackend(t, "IMAP4rev1 MOVE SPECIAL-USE", []writeStep{{contains: "LIST ", reply: listing + "{tag} OK listed\r\n"}})
			_, err := b.Trash(context.Background(), testWriteRef())
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("got %v, want unsupported", err)
			}
		})
	}
}

func TestTrashUsesAdvertisedFolderName(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 MOVE SPECIAL-USE", []writeStep{{contains: "LIST ", reply: "* LIST (\\Trash) \"/\" \"Deleted Messages\"\r\n{tag} OK listed\r\n"}, selectWriteStep(9, false), fetchFlagStep("", 0), {contains: `UID MOVE 17 "Deleted Messages"`, reply: "{tag} OK moved\r\n"}})
	got, err := b.Trash(context.Background(), testWriteRef())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "accepted" || got.Destination != nil || len(got.Warnings) == 0 {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestAppendDraftPreservesLiteralAndReturnsUID(t *testing.T) {
	raw := "From: owner@example.test\r\nTo: recipient@example.test\r\nSubject: Draft\r\n\r\nHello.\r\n"
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS SPECIAL-USE", []writeStep{{contains: "LIST ", reply: "* LIST (\\Drafts) \"/\" \"Draft Mail\"\r\n{tag} OK listed\r\n"}, {contains: `APPEND "Draft Mail" (\Draft)`, literal: raw, reply: "{tag} OK [APPENDUID 31 70] appended\r\n"}})
	got, err := b.AppendDraft(context.Background(), "", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "appended" || got.Destination == nil || *got.Destination != (Reference{Folder: "Draft Mail", UIDValidity: 31, UID: 70}) {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestAppendSentUsesDiscoveredSentFolder(t *testing.T) {
	raw := "From: owner@example.test\r\nTo: recipient@example.test\r\nSubject: Sent\r\n\r\nHello.\r\n"
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS SPECIAL-USE", []writeStep{{contains: "LIST ", reply: "* LIST (\\Sent) \"/\" \"Sent Items\"\r\n{tag} OK listed\r\n"}, {contains: `APPEND "Sent Items" (\Seen)`, literal: raw, reply: "{tag} OK [APPENDUID 32 71] appended\r\n"}})
	got, err := b.AppendSent(context.Background(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.Destination == nil || got.Destination.Folder != "Sent Items" {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestDeleteExpungesOnlyRequestedUIDThenVerifies(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS CONDSTORE", []writeStep{selectWriteStep(9, true), fetchFlagStep("", 12), {contains: `UID STORE 17 (UNCHANGEDSINCE 12) +FLAGS (\Deleted)`, reply: "* 4 FETCH (UID 17 FLAGS (\\Deleted) MODSEQ (13))\r\n{tag} OK flagged\r\n"}, {contains: "UID EXPUNGE 17", reply: "* 4 EXPUNGE\r\n{tag} OK expunged\r\n"}, {contains: "UID FETCH 17 ", reply: "{tag} OK absent\r\n"}})
	got, err := b.Delete(context.Background(), testWriteRef())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "deleted" {
		t.Fatalf("wrong result: %+v", got)
	}
}

func TestDeleteReportsPartialFailureWithoutGlobalExpunge(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS", []writeStep{selectWriteStep(9, false), fetchFlagStep("", 0), {contains: `UID STORE 17 +FLAGS (\Deleted)`, reply: "* 4 FETCH (UID 17 FLAGS (\\Deleted))\r\n{tag} OK flagged\r\n"}, {contains: "UID EXPUNGE 17", reply: "{tag} NO cannot expunge now\r\n"}})
	got, err := b.Delete(context.Background(), testWriteRef())
	if !errors.Is(err, ErrOutcomeUnknown) || got.Status != "marked_deleted" || len(got.Warnings) == 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDeleteNeverExpungesAfterConditionalConflict(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1 UIDPLUS CONDSTORE", []writeStep{selectWriteStep(9, true), fetchFlagStep("", 12), {contains: `UID STORE 17 (UNCHANGEDSINCE 12) +FLAGS (\Deleted)`, reply: "* 4 FETCH (UID 17 FLAGS (\\Deleted) MODSEQ (13))\r\n{tag} OK [MODIFIED 17] concurrent flags\r\n"}})
	got, err := b.Delete(context.Background(), testWriteRef())
	if !errors.Is(err, ErrConflict) || got.Status != "not_applied" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestCopyConnectionLossIsUnknownNotRetryableSuccess(t *testing.T) {
	b := writeTestBackend(t, "IMAP4rev1", []writeStep{selectWriteStep(9, false), fetchFlagStep("", 0), {contains: `UID COPY 17 "Archive"`, disconnect: true}})
	got, err := b.Copy(context.Background(), testWriteRef(), "Archive")
	if !errors.Is(err, ErrOutcomeUnknown) || got.Status != "unknown" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestFolderCreateAndRename(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		b := writeTestBackend(t, "IMAP4rev1", []writeStep{{contains: `CREATE "Work"`, reply: "{tag} OK created\r\n"}})
		if err := b.CreateFolder(context.Background(), "Work"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rename", func(t *testing.T) {
		b := writeTestBackend(t, "IMAP4rev1", []writeStep{{contains: `RENAME "Work" "Projects"`, reply: "{tag} OK renamed\r\n"}})
		if err := b.RenameFolder(context.Background(), "Work", "Projects"); err != nil {
			t.Fatal(err)
		}
	})
	b := &Backend{}
	if err := b.RenameFolder(context.Background(), "INBOX", "Archive"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("INBOX rename: %v", err)
	}
}

func TestMutationErrorsNeverLeakProviderText(t *testing.T) {
	err := commandMutationError(&imap.Error{Type: imap.StatusResponseTypeNo, Text: "secret provider diagnostic"})
	if err != ErrUnavailable || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe error: %v", err)
	}
	if err := commandMutationError(io.ErrUnexpectedEOF); err != ErrOutcomeUnknown {
		t.Fatalf("wrong network error: %v", err)
	}
}
