package remote_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"identity-agent-core/backup/remote"
	"identity-agent-core/backup/remote/fakedrive"
)

const testClient = "test-client.apps.example"

func newDrive(t *testing.T) (*fakedrive.Drive, remote.Backend) {
	t.Helper()
	d := fakedrive.New(testClient)
	t.Cleanup(d.Close)
	b, err := remote.NewGoogleDriveBackend(remote.DestinationConfig{Provider: "google_drive"},
		remote.CredentialSecrets{OAuthRefreshToken: d.GrantRefreshToken(), OAuthClientID: testClient}, d.Endpoints(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return d, b
}

func TestDriveWritesAnArchiveAndReadsItBack(t *testing.T) {
	d, b := newDrive(t)
	ctx := context.Background()
	archive := bytes.Repeat([]byte{0xA5, 0x01}, 3000)
	if err := b.Push(ctx, "aid1/backup-full-1.iab", archive); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(ctx, "aid1/backup-full-2.iab", []byte("newer")); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(ctx, "someone-else/backup-full-9.iab", []byte("not ours")); err != nil {
		t.Fatal(err)
	}
	keys, err := b.List(ctx, "aid1")
	if err != nil || len(keys) != 2 {
		t.Fatalf("list under prefix: %v %v", keys, err)
	}
	latest, err := remote.LatestArchiveKey(ctx, b, "aid1")
	if err != nil || latest != "aid1/backup-full-2.iab" {
		t.Fatalf("latest: %q %v", latest, err)
	}
	got, err := b.Pull(ctx, "aid1/backup-full-1.iab")
	if err != nil || !bytes.Equal(got, archive) {
		t.Fatalf("read back differs: %v", err)
	}
	if d.Refreshes != 1 {
		t.Fatalf("one access token should serve every call, refreshed %d times", d.Refreshes)
	}
}

func TestDriveRenewsAnAccessTokenThatHasExpired(t *testing.T) {
	d, b := newDrive(t)
	ctx := context.Background()
	if err := b.Push(ctx, "a/backup-full-1.iab", []byte("one")); err != nil {
		t.Fatal(err)
	}
	// An hour passes: the access token the backend holds is dead, and Drive says
	// so with a 401 in the middle of a run.
	d.ExpireAccessTokens()
	if err := b.Push(ctx, "a/backup-full-2.iab", []byte("two")); err != nil {
		t.Fatalf("an expired access token must be renewed, not fail the backup: %v", err)
	}
	if got, err := b.Pull(ctx, "a/backup-full-2.iab"); err != nil || string(got) != "two" {
		t.Fatalf("after renewal: %q %v", got, err)
	}
	if d.Refreshes != 2 {
		t.Fatalf("expected exactly one renewal, refreshes=%d", d.Refreshes)
	}
}

func TestDriveSaysSignInAgainWhenTheGrantIsGone(t *testing.T) {
	d, b := newDrive(t)
	d.RevokeGrant()
	err := b.Push(context.Background(), "a/backup-full-1.iab", []byte("x"))
	if !errors.Is(err, remote.ErrSignInExpired) {
		t.Fatalf("a revoked grant must be reported as a sign-in to redo, got %v", err)
	}
	if _, err := b.List(context.Background(), ""); !errors.Is(err, remote.ErrSignInExpired) {
		t.Fatalf("list: %v", err)
	}
}

func TestDriveSaysSoWhenTheAccountIsFull(t *testing.T) {
	d, b := newDrive(t)
	d.Full = true
	err := b.Push(context.Background(), "a/backup-full-1.iab", []byte("x"))
	if !errors.Is(err, remote.ErrDriveFull) {
		t.Fatalf("a full drive must be reported as one, got %v", err)
	}
	if len(d.Names()) != 0 {
		t.Fatalf("nothing should be left in a drive that refused the archive: %v", d.Names())
	}
}

func TestDriveRefusesAnArchiveChangedInTheDrive(t *testing.T) {
	d, b := newDrive(t)
	ctx := context.Background()
	key := "a/backup-full-1.iab"
	if err := b.Push(ctx, key, []byte("the archive")); err != nil {
		t.Fatal(err)
	}
	d.Tamper(key, []byte("the archivE"))
	if _, err := b.Pull(ctx, key); !errors.Is(err, remote.ErrArchiveChanged) {
		t.Fatalf("changed bytes must be refused, got %v", err)
	}
	// Truncation is a change too.
	d.Tamper(key, []byte("the arch"))
	if _, err := b.Pull(ctx, key); !errors.Is(err, remote.ErrArchiveChanged) {
		t.Fatalf("truncated bytes must be refused, got %v", err)
	}
	// A file with no recorded digest was not written by us.
	d.Tamper(key, []byte("the archive"))
	d.StripDigest(key)
	if _, err := b.Pull(ctx, key); !errors.Is(err, remote.ErrArchiveChanged) {
		t.Fatalf("a file with no digest must be refused, got %v", err)
	}
}

func TestDriveOnlyEverAsksForTheAppFolder(t *testing.T) {
	// The stand-in refuses any listing that is not of appDataFolder, and any
	// upload whose parent is not appDataFolder. Passing is the proof.
	_, b := newDrive(t)
	ctx := context.Background()
	if err := b.Push(ctx, "a/backup-full-1.iab", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.List(ctx, ""); err != nil {
		t.Fatal(err)
	}
}

func TestDriveNamesWithQuotesAreFoundExactly(t *testing.T) {
	_, b := newDrive(t)
	ctx := context.Background()
	key := `a/it's \ here.iab`
	if err := b.Push(ctx, key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Pull(ctx, key); err != nil || string(got) != "x" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := b.Pull(ctx, "a/missing.iab"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing: %v", err)
	}
}

func TestDriveNeedsASignIn(t *testing.T) {
	if _, err := remote.NewGoogleDriveBackend(remote.DestinationConfig{}, remote.CredentialSecrets{}, remote.GoogleEndpoints{}, nil); err == nil {
		t.Fatal("a Drive destination with no sign-in must not construct")
	}
}
