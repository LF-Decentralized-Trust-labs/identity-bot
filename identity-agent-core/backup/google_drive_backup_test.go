package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/backup/remote"
	"identity-agent-core/backup/remote/fakedrive"
)

const driveTestClient = "agent-app.apps.example"

// aServiceSignedInTo returns a Service with its own data directory, whose
// destination factory talks to the stand-in, and which has completed the whole
// sign-in the way the app would.
func aServiceSignedInTo(t *testing.T, d *fakedrive.Drive) (*Service, Destination) {
	t.Helper()
	orig := remoteBackendFactory
	remoteBackendFactory = func(dest Destination, creds RemoteCredentialSecrets) (remoteBackend, error) {
		return remote.NewGoogleDriveBackend(toRemoteDestination(dest), toRemoteCredentials(creds), d.Endpoints(), nil)
	}
	t.Cleanup(func() { remoteBackendFactory = orig })

	svc := NewService(t.TempDir(), nil)
	svc.Google = &GoogleSignIn{ClientID: driveTestClient, Endpoints: d.Endpoints()}
	redirect := "http://127.0.0.1:53682/callback"
	authURL, state, err := svc.StartGoogleSignIn(redirect)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if q.Get("scope") != remote.GoogleAppDataScope || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != driveTestClient || q.Get("state") != state || q.Get("access_type") != "offline" {
		t.Fatalf("authorisation URL asks for the wrong thing: %s", authURL)
	}
	code := d.IssueCode(q.Get("code_challenge"))
	dest, err := svc.CompleteGoogleSignIn(state, code, redirect)
	if err != nil {
		t.Fatal(err)
	}
	return svc, dest
}

func aSealedArchive(t *testing.T) []byte {
	t.Helper()
	plain, _ := SerializePayloadBundle(&PayloadBundle{Ordered: []PayloadSection{{Name: "test", Data: []byte("hello")}}})
	bek, _ := NewBEK()
	ct, nonce, _ := EncryptPayload(bek, plain)
	kek, _ := SeedKEKFromMnemonic(testMnemonic)
	wrapped, wrapNonce, _ := WrapBEK(kek, bek)
	m := NewManifest("Eidentity-one", []string{TierCritical}, "full")
	m.PayloadNonceB64 = EncodeB64(nonce)
	m.KeySlots = []KeySlot{{Type: SlotSeedHD, WrappedBEKB64: EncodeB64(wrapped), NonceB64: EncodeB64(wrapNonce)}}
	m.Sections = []SectionMeta{{Name: "test", DigestBlake3QB64: DigestSectionMust([]byte("hello")), SizePlaintext: 5}}
	raw, err := EncodeArchive(&ArchiveFile{Manifest: m, Ciphertext: ct})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSigningInMakesADriveDestinationAndKeepsTheGrantWithTheSecrets(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc, dest := aServiceSignedInTo(t, d)

	if dest.Type != DestCloudUser || dest.CloudProvider != GoogleProviderName || !dest.Enabled {
		t.Fatalf("destination: %+v", dest)
	}
	cfg, _ := svc.LoadConfig()
	if len(cfg.Destinations) != 1 || cfg.Destinations[0].CredentialID != dest.CredentialID {
		t.Fatalf("destination not saved: %+v", cfg.Destinations)
	}
	creds, err := svc.CredentialStore.Load(dest.CredentialID)
	if err != nil || creds.OAuthRefreshToken == "" || creds.OAuthClientID != driveTestClient {
		t.Fatalf("grant not kept: %+v %v", creds, err)
	}
	// Neither the config nor any file in the data directory holds the token in
	// the clear.
	filepath.Walk(svc.DataDir, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(creds.OAuthRefreshToken)) {
				t.Errorf("the refresh token is readable in %s", p)
			}
		}
		return nil
	})
	if ElsewhereOf(dest, svc.DataDir) != ElsewhereYes {
		t.Fatal("a cloud drive is somewhere else")
	}
}

func TestDriveSignInRefusesWhatIsNotExactlyTheAppFolder(t *testing.T) {
	redirect := "http://localhost:1/cb"
	for name, setup := range map[string]func(d *fakedrive.Drive){
		"a wider scope": func(d *fakedrive.Drive) { d.GrantedScope = "https://www.googleapis.com/auth/drive" },
		"an extra scope": func(d *fakedrive.Drive) {
			d.GrantedScope = fakedrive.Scope + " https://www.googleapis.com/auth/drive.file"
		},
		"no scope":         func(d *fakedrive.Drive) { d.GrantedScope = "" },
		"no refresh token": func(d *fakedrive.Drive) { d.OmitRefreshToken = true },
	} {
		t.Run(name, func(t *testing.T) {
			d := fakedrive.New(driveTestClient)
			defer d.Close()
			setup(d)
			svc := NewService(t.TempDir(), nil)
			svc.Google = &GoogleSignIn{ClientID: driveTestClient, Endpoints: d.Endpoints()}
			authURL, state, _ := svc.StartGoogleSignIn(redirect)
			u, _ := url.Parse(authURL)
			if _, err := svc.CompleteGoogleSignIn(state, d.IssueCode(u.Query().Get("code_challenge")), redirect); err == nil {
				t.Fatal("this grant must not be kept")
			}
			if cfg, _ := svc.LoadConfig(); len(cfg.Destinations) != 0 {
				t.Fatalf("a destination was made anyway: %+v", cfg.Destinations)
			}
			entries, _ := os.ReadDir(filepath.Join(svc.DataDir, "backup"))
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".enc") {
					t.Fatalf("a credential was written anyway: %s", e.Name())
				}
			}
		})
	}
}

func TestDriveSignInStateIsOneUseAndTheRedirectIsFixed(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc := NewService(t.TempDir(), nil)
	svc.Google = &GoogleSignIn{ClientID: driveTestClient, Endpoints: d.Endpoints()}
	redirect := "http://127.0.0.1:9/cb"
	authURL, state, _ := svc.StartGoogleSignIn(redirect)
	u, _ := url.Parse(authURL)
	ch := u.Query().Get("code_challenge")

	if _, err := svc.CompleteGoogleSignIn("not-a-state", d.IssueCode(ch), redirect); err == nil {
		t.Fatal("a state this core never issued must be refused")
	}
	if _, err := svc.CompleteGoogleSignIn(state, d.IssueCode(ch), "http://127.0.0.1:10/cb"); err == nil {
		t.Fatal("a different redirect must be refused")
	}
	// The failed attempt above spent the state.
	if _, err := svc.CompleteGoogleSignIn(state, d.IssueCode(ch), redirect); err == nil {
		t.Fatal("a state is good for one attempt")
	}
	for _, bad := range []string{"https://evil.example/cb", "http://evil.example/cb", "", "no-scheme"} {
		if _, _, err := svc.StartGoogleSignIn(bad); err == nil {
			t.Errorf("redirect %q must be refused", bad)
		}
	}
	if _, _, err := svc.StartGoogleSignIn("com.example.agent:/oauth2redirect"); err != nil {
		t.Errorf("an app's own scheme is a valid redirect: %v", err)
	}
	// And a code is bound to the verifier that started it.
	_, state2, _ := svc.StartGoogleSignIn(redirect)
	if _, err := svc.CompleteGoogleSignIn(state2, d.IssueCode("somebody-elses-challenge"), redirect); err == nil {
		t.Fatal("a code issued against another challenge must not exchange")
	}
}

func TestDriveSignInNeedsAClientFromTheBuild(t *testing.T) {
	t.Setenv(GoogleClientIDEnv, "")
	svc := NewService(t.TempDir(), nil)
	if _, _, err := svc.StartGoogleSignIn("http://127.0.0.1:1/cb"); err == nil || !strings.Contains(err.Error(), GoogleClientIDEnv) {
		t.Fatalf("with no client the error must say what is missing, got %v", err)
	}
}

func TestAnArchiveWrittenToDriveRestoresOntoADifferentMachine(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	machineA, destA := aServiceSignedInTo(t, d)

	archive := aSealedArchive(t)
	if err := machineA.pushCloudDestination(destA, &ExportResult{Bytes: archive, SnapshotType: SnapshotFull, Size: len(archive)}); err != nil {
		t.Fatal(err)
	}
	if len(d.Names()) != 1 || !bytes.Equal(d.Bytes(d.Names()[0]), archive) {
		t.Fatal("what reached Drive is not the archive the core made, byte for byte")
	}

	// Machine A is gone. Machine B has nothing: no destinations, no credentials,
	// a different data directory. The person signs in to the same Google account.
	machineB, destB := aServiceSignedInTo(t, d)
	if machineB.DataDir == machineA.DataDir {
		t.Fatal("test is not using a different machine")
	}
	got, key, err := machineB.PullLatestArchive(destB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, archive) || !strings.HasSuffix(key, ".iab") {
		t.Fatal("the restored archive differs")
	}
	// And it is the archive that opens with the recovery words alone.
	if _, _, err := OpenArchive(got, OpenRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("the archive read back does not open: %v", err)
	}
}

func TestRestoreFromADriveHoldingTwoIdentitiesAsksWhich(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc, dest := aServiceSignedInTo(t, d)
	creds, _ := svc.CredentialStore.Load(dest.CredentialID)
	be, _ := remoteBackendFactory(dest, creds)
	for _, k := range []string{"Eone/backup-full-1.iab", "Etwo/backup-full-2.iab"} {
		if err := be.Push(context.Background(), k, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	dest.CloudPrefix = ""
	if _, _, err := svc.PullLatestArchive(dest); err == nil || !strings.Contains(err.Error(), "more than one identity") {
		t.Fatalf("restoring with no identity named from a drive holding two must ask which, got %v", err)
	}
	dest.CloudPrefix = "Eone"
	if got, _, err := svc.PullLatestArchive(dest); err != nil || string(got) != "Eone/backup-full-1.iab" {
		t.Fatalf("naming the identity: %q %v", got, err)
	}
}

func TestABackupSurvivesAnExpiredAccessTokenAndSaysWhenSignInIsNeeded(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc, dest := aServiceSignedInTo(t, d)
	archive := aSealedArchive(t)
	res := &ExportResult{Bytes: archive, SnapshotType: SnapshotFull, Size: len(archive)}

	if err := svc.pushCloudDestination(dest, res); err != nil {
		t.Fatal(err)
	}
	d.ExpireAccessTokens() // the next run is an hour later: a new backend, and a stale world
	if err := svc.pushCloudDestination(dest, res); err != nil {
		t.Fatalf("an expired token is renewed, not a failed backup: %v", err)
	}

	d.RevokeGrant()
	err := svc.pushCloudDestination(dest, res)
	if !errors.Is(err, remote.ErrSignInExpired) {
		t.Fatalf("a revoked grant must say sign in again, got %v", err)
	}
	// and through the real path, the destination records it for the screen
	cfg, _ := svc.LoadConfig()
	svc.pushToDestinations(cfg, res)
	cfg, _ = svc.LoadConfig()
	if !strings.Contains(cfg.Destinations[0].LastError, "sign in again") {
		t.Fatalf("the destination does not say what to do: %q", cfg.Destinations[0].LastError)
	}
}

func TestAFullDriveIsReportedOnTheDestination(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc, _ := aServiceSignedInTo(t, d)
	d.Full = true
	archive := aSealedArchive(t)
	res := &ExportResult{Bytes: archive, SnapshotType: SnapshotFull, Size: len(archive)}
	cfg, _ := svc.LoadConfig()
	if ids := svc.pushToDestinations(cfg, res); len(ids) != 0 {
		t.Fatalf("a full drive took the archive? %v", ids)
	}
	cfg, _ = svc.LoadConfig()
	got := cfg.Destinations[0]
	if !strings.Contains(got.LastError, "out of storage") || got.LastSuccessAt != "" {
		t.Fatalf("a full drive must be said on the destination and not counted as a success: %+v", got)
	}
}

func TestAnArchiveChangedInTheDriveIsRefusedOnRestore(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc, dest := aServiceSignedInTo(t, d)
	archive := aSealedArchive(t)
	if err := svc.pushCloudDestination(dest, &ExportResult{Bytes: archive, SnapshotType: SnapshotFull, Size: len(archive)}); err != nil {
		t.Fatal(err)
	}
	name := d.Names()[0]

	// 1. Bytes changed in the drive, digest left behind.
	changed := append([]byte(nil), archive...)
	changed[len(changed)-3] ^= 0xFF
	d.Tamper(name, changed)
	if _, _, err := svc.PullLatestArchive(dest); !errors.Is(err, remote.ErrArchiveChanged) {
		t.Fatalf("a changed archive must be refused by the destination, got %v", err)
	}

	// 2. Someone with full access to the folder also rewrites the digest. The
	// destination now accepts it; the archive itself must still refuse to open.
	d.TamperAll(name, changed)
	got, _, err := svc.PullLatestArchive(dest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenArchive(got, OpenRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("an archive altered in the drive, digest and all, opened")
	}
}

func TestARefusedGrantIsCancelledAtGoogle(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	d.GrantedScope = "https://www.googleapis.com/auth/drive"
	svc := NewService(t.TempDir(), nil)
	svc.Google = &GoogleSignIn{ClientID: driveTestClient, Endpoints: d.Endpoints()}
	redirect := "http://127.0.0.1:1/cb"
	authURL, state, _ := svc.StartGoogleSignIn(redirect)
	u, _ := url.Parse(authURL)
	if _, err := svc.CompleteGoogleSignIn(state, d.IssueCode(u.Query().Get("code_challenge")), redirect); err == nil {
		t.Fatal("a wider grant was kept")
	}
	if len(d.Revoked) != 2 {
		t.Fatalf("the refused refresh and access tokens must both be cancelled at Google, revoked %v", d.Revoked)
	}
}

func TestARestoredMachineFilesItsNextBackupWithTheOldOnes(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	// Signed in before any identity exists on this machine: the prefix is empty.
	svc, dest := aServiceSignedInTo(t, d)
	if dest.CloudPrefix != "" {
		t.Fatalf("test needs a machine with no identity yet, prefix %q", dest.CloudPrefix)
	}
	be, _ := remoteBackendFactory(dest, mustCreds(t, svc, dest))
	if err := be.Push(context.Background(), "Eold/backup-full-20250101-000000.iab", []byte("old")); err != nil {
		t.Fatal(err)
	}
	// The identity is restored here, then a backup runs.
	svc.Store = aCollectorForAnIdentity(t, "Eold").Store
	archive := aSealedArchive(t)
	if err := svc.pushCloudDestination(dest, &ExportResult{Bytes: archive, SnapshotType: SnapshotFull, Size: len(archive)}); err != nil {
		t.Fatal(err)
	}
	for _, n := range d.Names() {
		if !strings.HasPrefix(n, "Eold/") {
			t.Fatalf("a backup was filed outside the identity's prefix: %q (all: %v)", n, d.Names())
		}
	}
	if _, key, err := svc.PullLatestArchive(dest); err != nil || !strings.HasPrefix(key, "Eold/") {
		t.Fatalf("restore after that: %q %v", key, err)
	}
}

func TestDriveListingFollowsEveryPage(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	d.PageSize = 2
	svc, dest := aServiceSignedInTo(t, d)
	be, _ := remoteBackendFactory(dest, mustCreds(t, svc, dest))
	for i := 1; i <= 5; i++ {
		if err := be.Push(context.Background(), fmt.Sprintf("Ea/backup-full-%d.iab", i), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := be.List(context.Background(), "Ea")
	if err != nil || len(keys) != 5 {
		t.Fatalf("five archives over three pages: %v %v", keys, err)
	}
}

func TestOnlyAnAppsOwnSchemeOrLoopbackIsARedirect(t *testing.T) {
	for _, bad := range []string{"javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "myapp:/cb", "http://localhost@evil.example/cb"} {
		if redirectAllowed(bad) == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:5/cb", "http://[::1]:5/cb", "com.example.agent:/oauth2redirect"} {
		if err := redirectAllowed(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func mustCreds(t *testing.T, svc *Service, dest Destination) RemoteCredentialSecrets {
	t.Helper()
	c, err := svc.CredentialStore.Load(dest.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnArchiveIsFetchedToDiskAndLeavesNothingWhenItFails(t *testing.T) {
	d := fakedrive.New(driveTestClient)
	defer d.Close()
	svc, dest := aServiceSignedInTo(t, d)
	archive := aSealedArchive(t)
	if err := svc.pushCloudDestination(dest, &ExportResult{Bytes: archive, SnapshotType: SnapshotFull, Size: len(archive)}); err != nil {
		t.Fatal(err)
	}
	path, key, size, done, err := svc.PullLatestArchiveToFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(path)
	if !bytes.Equal(onDisk, archive) || size != int64(len(archive)) || !strings.HasSuffix(key, ".iab") {
		t.Fatal("what was written to disk is not the archive")
	}
	if skipReason(filepath.ToSlash(mustRel(t, svc.DataDir, path))) == "" {
		t.Fatal("the fetched archive would be carried by the next backup")
	}
	done()
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("done did not remove the working directory")
	}

	d.Tamper(d.Names()[0], []byte("not it"))
	if _, _, _, _, err := svc.PullLatestArchiveToFile(dest); !errors.Is(err, remote.ErrArchiveChanged) {
		t.Fatalf("a changed archive must be refused: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(svc.DataDir, RestoringPrefix+"fetch-*"))
	if len(left) != 0 {
		t.Fatalf("a refused download left %v behind", left)
	}
}

func mustRel(t *testing.T, base, p string) string {
	t.Helper()
	r, err := filepath.Rel(base, p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
