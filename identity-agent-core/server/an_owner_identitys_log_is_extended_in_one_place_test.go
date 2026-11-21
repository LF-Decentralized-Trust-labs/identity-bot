package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/endpoint"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/ownership"
	"identity-agent-core/store"
)

// Two Identity Agents an owner identity might be asked to anchor, and a later
// establishment event of the first.
const (
	aMachine          = "EMachineOneMachineOneMachineOneMachineOne000"
	anotherMachine    = "EMachineTwoMachineTwoMachineTwoMachineTwo000"
	aMachinesRotation = "ERotationOfMachineOneRotationOfMachineOne000"
)

var errTheDeviceStopped = errors.New("the device stopped")

// restartedOver is the core started again over the same data: a new engine
// that holds nothing, the store opened again, and the key logs handed back.
func restartedOver(t *testing.T, was *CoreServer) *CoreServer {
	t.Helper()
	ds, err := store.NewSQLiteStore(was.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ds.Close() })
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: was.DataDir, DataStore: ds, EventHub: NewEventHub()}
	endsItsBackgroundWork(t, s)
	eng := keriengine.New()
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}
	s.KeriDriver = eng
	s.EndpointService = endpoint.New(nil, 0)
	// What the witnesses are is carried over: a stand-in where the test gave
	// one, and otherwise what a running core has.
	s.ownerLog.witnesses = was.ownerLog.witnesses
	s.reloadKeyLogs()
	return s
}

// witnessesThatAgree stands in for an owner identity's witnesses: they hold
// whatever this device keeps, and receipt whatever it sends. It makes no
// check, so it shows what the writer does with the check passed, and nothing
// about whether it should have passed.
type witnessesThatAgree struct{}

func (witnessesThatAgree) continuesFromWhatTheyHold(string, *drivers.DriverKelResponse) error {
	return nil
}

func (witnessesThatAgree) await(string, int) error { return nil }

// withWitnessesStandingIn has s's owner log writer ask witnessesThatAgree.
func withWitnessesStandingIn(s *CoreServer) *CoreServer {
	s.ownerLog.witnesses = witnessesThatAgree{}
	return s
}

// backupOf is a copy of s's database as it is now, as a backup holds it.
func backupOf(t *testing.T, s *CoreServer) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), "identity.db")
	if _, err := s.DataStore.(*store.SQLiteStore).DB().Exec(`VACUUM INTO ?`, to); err != nil {
		t.Fatal(err)
	}
	return to
}

// restoredFrom is the core started over s's data directory with its database
// replaced by backup: the same root seed and everything else on the device,
// and the database as it was when the backup was made.
func restoredFrom(t *testing.T, s *CoreServer, backup string) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir(s.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(s.DataDir, path)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dir, rel), 0o700)
		}
		if strings.HasPrefix(d.Name(), "identity.db") {
			return nil
		}
		return copyFile(path, filepath.Join(dir, rel))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFile(backup, filepath.Join(dir, "identity.db")); err != nil {
		t.Fatal(err)
	}
	return restartedOver(t, &CoreServer{DataDir: dir, ownerLog: ownerLogState{witnesses: s.ownerLog.witnesses}})
}

func copyFile(from, to string) error {
	raw, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, raw, 0o600)
}

// keptOwnerLog is an owner identity's key log as the store keeps it, which
// must be one whole log that verifies.
func keptOwnerLog(t *testing.T, s *CoreServer, owner string) []store.EventRecord {
	t.Helper()
	events, messages := keptOwnerLogMessages(t, s, owner)
	if _, err := drivers.VerifiedLogOf(owner, messages); err != nil {
		t.Fatalf("the kept log of %s does not verify: %v", owner, err)
	}
	return events
}

// keptOwnerLogMessages is the kept log of an owner identity as a verifier is
// handed it: each event with its signatures attached.
func keptOwnerLogMessages(t *testing.T, s *CoreServer, owner string) ([]store.EventRecord, [][]byte) {
	t.Helper()
	events, err := s.DataStore.GetEvents(owner)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := store.SignedLogOf(events)
	if err != nil {
		t.Fatalf("the kept log of %s: %v", owner, err)
	}
	messages, err := drivers.StoredLogMessages(signed)
	if err != nil {
		t.Fatal(err)
	}
	return events, messages
}

func mintedOwnerOf(t *testing.T, s *CoreServer, kind string) string {
	t.Helper()
	aid, _, err := s.mintAnIdentityToClaimAMachineWith(kind)
	if err != nil {
		t.Fatal(err)
	}
	return aid
}

// An owner identity minted in one run of the core has its log extended in
// the next: the engine is handed the log at start, the key is found from the
// stored index, and the event written is the event seal ADR-087 decision 1
// states, in a log that verifies from its founding.
func TestAnOwnerIdentitysLogIsExtendedAfterTheCoreRestarts(t *testing.T) {
	first := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, first, machineKindIndividual)

	s := restartedOver(t, first)
	held, err := s.KeriDriver.(interface {
		GetKelByAID(string) (*drivers.DriverKelResponse, error)
	}).GetKelByAID(owner)
	if err != nil || held.EventCount != 1 {
		t.Fatalf("after a restart the engine does not hold the owner identity's log: %v", err)
	}

	ev, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
	if err != nil {
		t.Fatalf("the log could not be extended after a restart: %v", err)
	}
	if !ev.Written || ev.SN != 1 || len(ev.Signatures) == 0 {
		t.Fatalf("wrote %+v", ev)
	}
	kept := keptOwnerLog(t, s, owner)
	if len(kept) != 2 || kept[1].EventType != "ixn" {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	var ixn struct {
		A []json.RawMessage `json:"a"`
	}
	if err := json.Unmarshal(ev.Raw, &ixn); err != nil {
		t.Fatal(err)
	}
	want := `{"i":"` + aMachine + `","s":"0","d":"` + aMachine + `"}`
	if len(ixn.A) != 1 || string(ixn.A[0]) != want {
		t.Fatalf("the interaction anchors %s, want exactly %s", ixn.A, want)
	}

	// And again after another restart: a later event of the same Identity
	// Agent, chained to the anchor the last run wrote.
	s = restartedOver(t, s)
	later, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation)
	if err != nil || later.SN != 2 {
		t.Fatalf("the second anchor: %+v, %v", later, err)
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 3 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	// What is served to whoever resolves the identity is the kept log.
	if served, _ := s.getPairwiseKEL(owner); len(served) != 3 {
		t.Fatalf("the served copy has %d events and the kept log 3", len(served))
	}
}

// What the writer leaves in an owner log is what ADR-087 calls owned: the
// owner log after it anchors a machine's founding, with that machine's log,
// passes the ownership check as anchored. A look-alike that names the same
// owner, and that the owner never anchored, is only named.
func TestAnOwnerLogTheWriterExtendedPassesTheOwnershipCheck(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	names, err := keriengine.OwnerSeal(owner)
	if err != nil {
		t.Fatal(err)
	}
	foundedNaming := func() *signedlog.Log {
		return signedlog.InceptWith(t, signedlog.NewKeys(t, 2),
			keri.InceptionInput{Data: []json.RawMessage{names}})
	}
	machine, lookAlike := foundedNaming(), foundedNaming()

	ev, err := s.anchorInOwnerLog(owner, machine.AID, 0, machine.SAID(0))
	if err != nil || !ev.Written {
		t.Fatalf("the anchor: %+v, %v", ev, err)
	}
	_, ownerLog := keptOwnerLogMessages(t, s, owner)
	handed := func(messages [][]byte) ownership.Log {
		return ownership.Log{Messages: messages, Source: ownership.FromTheCheckedParty}
	}

	got := ownership.Check(handed(machine.Messages()), handed(ownerLog), ownership.Options{})
	if got.Grade != ownership.OwnedAnchored || !got.Owned() {
		t.Fatalf("the anchored machine is %s (%s): %s", got.Grade, got.Reason, got.Detail)
	}
	if got.Machine != machine.AID || got.Owner != owner || got.AnchoredBy != ev.SAID {
		t.Fatalf("the check names %s owned by %s, anchored by %s; want %s, %s, %s",
			got.Machine, got.Owner, got.AnchoredBy, machine.AID, owner, ev.SAID)
	}

	got = ownership.Check(handed(lookAlike.Messages()), handed(ownerLog), ownership.Options{})
	if got.Grade != ownership.NamedNotOwned || got.Reason != ownership.NamedNotAnchored || got.Owned() {
		t.Fatalf("a look-alike the owner never anchored is %s (%s): %s", got.Grade, got.Reason, got.Detail)
	}
}

// Once a place is reserved, the owner identity's key signs the reserved bytes
// there and no others, whoever asks.
func TestASecondDigestIsNeverSignedAtAReservedPlace(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)

	// The device stops with place 1 reserved for the founding of the machine,
	// and nothing signed.
	s.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	s.ownerLog.stopAt = nil
	reserved, err := s.DataStore.OwnerLogReservations(owner)
	if err != nil || len(reserved) != 1 || reserved[0].SN != 1 || reserved[0].State != store.OwnerLogReserved {
		t.Fatalf("the reservations are %+v, %v", reserved, err)
	}

	// Another event built for the same place is not signed: not when the
	// engine's signer is asked directly, and not when the engine is asked to
	// append it.
	eng := s.KeriDriver.(ownerLogEngine)
	name, _, _ := eng.NameHolding(owner)
	seal, _ := drivers.EventSeal(aMachine, "1", aMachinesRotation)
	other, err := eng.Prepare(keriengine.PrepareRequest{Name: name, Ilk: "ixn", Anchors: []json.RawMessage{seal}})
	if err != nil {
		t.Fatal(err)
	}
	if other.Hint.D == reserved[0].Digest {
		t.Fatal("test setup: the second event is the first")
	}
	if sig, err := s.signEventFor(owner, "", other.Raw); err == nil {
		t.Fatalf("a second digest was signed at a reserved place: %s", sig)
	}
	if _, err := s.KeriDriver.(drivers.KELKeeper).InteractKept(name, []interface{}{seal}, nil); err == nil {
		t.Fatal("the engine appended an event that was never reserved")
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 1 {
		t.Fatalf("the kept log has %d events", len(kept))
	}

	// Asking for that other anchor finishes the reserved event first, at the
	// reserved place, and writes the other after it.
	ev, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation)
	if err != nil || ev.SN != 2 {
		t.Fatalf("the other anchor: %+v, %v", ev, err)
	}
	kept := keptOwnerLog(t, s, owner)
	if len(kept) != 3 || kept[1].RawBytesB64 != reserved[0].RawB64 {
		t.Fatal("the event at the reserved place is not the one reserved")
	}
}

// Wherever the device stops, the event at a reserved place is the reserved
// bytes: the same bytes are signed when the core starts again, or when the
// anchor is asked for again, and one event is written.
func TestACrashBetweenReservingAndSigningSignsTheSameBytesLater(t *testing.T) {
	for _, stop := range []ownerLogStep{ownerLogBeforeReserving, ownerLogReserved, ownerLogSigned, ownerLogSaved} {
		for _, resume := range []string{"the core starts again", "the anchor is asked for again"} {
			t.Run("stopped "+string(stop)+", then "+resume, func(t *testing.T) {
				s := withWitnessesStandingIn(adoptingOwner(t))
				owner := mintedOwnerOf(t, s, machineKindIndividual)
				s.ownerLog.stopAt = func(at ownerLogStep) error {
					if at == stop {
						return errTheDeviceStopped
					}
					return nil
				}
				if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
					t.Fatalf("the writer did not stop %s: %v", stop, err)
				}
				s.ownerLog.stopAt = nil

				reserved, err := s.DataStore.OwnerLogReservations(owner)
				if err != nil {
					t.Fatal(err)
				}
				kept := keptOwnerLog(t, s, owner)
				switch stop {
				case ownerLogBeforeReserving:
					if len(reserved) != 0 || len(kept) != 1 {
						t.Fatalf("stopped before reserving, with %d reserved and %d kept", len(reserved), len(kept))
					}
				case ownerLogReserved, ownerLogSigned:
					if len(reserved) != 1 || reserved[0].State != store.OwnerLogReserved || len(kept) != 1 {
						t.Fatalf("stopped %s, with %+v reserved and %d kept", stop, reserved, len(kept))
					}
				case ownerLogSaved:
					if len(reserved) != 1 || reserved[0].State != store.OwnerLogDone || len(kept) != 2 {
						t.Fatalf("stopped after the save, with %+v reserved and %d kept", reserved, len(kept))
					}
				}

				if resume == "the core starts again" {
					s = restartedOver(t, s)
					if stop != ownerLogBeforeReserving {
						// Finished at start, before anybody asks.
						if kept := keptOwnerLog(t, s, owner); len(kept) != 2 || kept[1].RawBytesB64 != reserved[0].RawB64 {
							t.Fatalf("starting again did not finish the reserved event: %d kept", len(kept))
						}
					}
				}
				ev, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
				if err != nil || ev.SN != 1 {
					t.Fatalf("after resuming: %+v, %v", ev, err)
				}
				kept = keptOwnerLog(t, s, owner)
				if len(kept) != 2 {
					t.Fatalf("the kept log has %d events, want the founding and one anchor", len(kept))
				}
				after, _ := s.DataStore.OwnerLogReservations(owner)
				if len(after) != 1 || after[0].State != store.OwnerLogDone || after[0].RawB64 != kept[1].RawBytesB64 {
					t.Fatalf("the reservation is %+v and does not match the kept event", after)
				}
				if len(reserved) == 1 && reserved[0].RawB64 != kept[1].RawBytesB64 {
					t.Fatal("the bytes signed later are not the bytes reserved")
				}
				// The engine holds what the store keeps, so the next event
				// chains to it.
				if next, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation); err != nil || next.SN != 2 {
					t.Fatalf("the next anchor: %+v, %v", next, err)
				}
				keptOwnerLog(t, s, owner)
			})
		}
	}
}

// The same anchor asked for twice is one event, returned both times.
func TestAnAnchorAskedForTwiceWritesOneEvent(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)

	first, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
	if err != nil || !first.Written {
		t.Fatalf("the first: %+v, %v", first, err)
	}
	again, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
	if err != nil {
		t.Fatal(err)
	}
	if again.Written || again.SN != first.SN || again.SAID != first.SAID || string(again.Raw) != string(first.Raw) ||
		len(again.Signatures) == 0 {
		t.Fatalf("asked again, got %+v, want the event first written (%s at %d)", again, first.SAID, first.SN)
	}
	// And after a restart, from the kept log.
	s = restartedOver(t, s)
	if third, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err != nil || third.Written || third.SAID != first.SAID {
		t.Fatalf("asked after a restart, got %+v, %v", third, err)
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 2 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	if res, _ := s.DataStore.OwnerLogReservations(owner); len(res) != 1 {
		t.Fatalf("%d places were reserved", len(res))
	}
}

// One owner identity owns one Identity Agent (ADR-087 decision 8): an anchor
// naming a second is refused and nothing is reserved or signed for it, though
// a later event of the first is anchored.
func TestAnOwnerLogThatAlreadyNamesOneIdentityAgentRefusesASecond(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err != nil {
		t.Fatal(err)
	}

	if _, err := s.anchorInOwnerLog(owner, anotherMachine, 0, anotherMachine); !errors.Is(err, store.ErrOwnerLogNamesAnother) {
		t.Fatalf("a second Identity Agent was anchored: %v", err)
	}
	// The log is read too, so a device whose record beside it was lost and
	// rebuilt still refuses.
	if _, err := s.DataStore.(*store.SQLiteStore).DB().Exec(`UPDATE machine_owner_identities SET anchored_m = ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.anchorInOwnerLog(owner, anotherMachine, 0, anotherMachine); !errors.Is(err, store.ErrOwnerLogNamesAnother) {
		t.Fatalf("with its record lost, a second Identity Agent was anchored: %v", err)
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 2 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	if res, _ := s.DataStore.OwnerLogReservations(owner); len(res) != 1 {
		t.Fatalf("%d places were reserved", len(res))
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation); err != nil {
		t.Fatalf("a later event of the same Identity Agent was refused: %v", err)
	}

	// An identity this device did not mint has no log here to extend.
	if _, err := s.anchorInOwnerLog(aMachinesRotation, aMachine, 0, aMachine); !errors.Is(err, store.ErrNotAnOwnerIdentity) {
		t.Fatalf("an identity never minted here was written to: %v", err)
	}
}

// A given-up owner identity anchors nothing and signs no owner request, and
// still signs the claim a machine was told to expect from it (ADR-087
// decision 7). One whose log is known to hold two events at one place
// anchors nothing either.
func TestAGivenUpOwnerIdentityAnchorsNothingAndSignsNoOwnerRequestAndStillSignsItsClaim(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err != nil {
		t.Fatal(err)
	}
	signs := `{"owner_aid":"` + owner + `","method":"GET","path":"/api/identity","for":"` + aMachine + `"}`
	if rec := askToSignAs(t, s, signs); rec.Code != http.StatusOK {
		t.Fatalf("before it is given up it signs: %d %s", rec.Code, rec.Body.String())
	}

	if err := s.DataStore.GiveUpMachineOwnerIdentity(owner, aMachine); err != nil {
		t.Fatal(err)
	}

	if _, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation); !errors.Is(err, store.ErrOwnerIdentityGivenUp) {
		t.Fatalf("a given-up owner identity anchored: %v", err)
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 2 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	if rec := askToSignAs(t, s, signs); rec.Code != http.StatusForbidden {
		t.Fatalf("a given-up owner identity signed an owner request: %d %s", rec.Code, rec.Body.String())
	}

	// The claim a machine was told to expect from it is still signed, with
	// the key that machine will check.
	id, _, _ := s.DataStore.MachineOwnerIdentity(owner)
	sig, err := s.signClaim(id.KeyIndex, "challenge", "token", owner, "DOfferedKey")
	if err != nil {
		t.Fatalf("a given-up owner identity could not sign its claim: %v", err)
	}
	pub, _ := s.pairwisePublicKey(id.KeyIndex)
	verkey, _ := login.DecodeVerkey(pub)
	if ok, err := login.VerifyString(string(claimSigningInput("challenge", "token", owner, "DOfferedKey")), sig, verkey); err != nil || !ok {
		t.Fatalf("the claim does not verify: %v", err)
	}

	// Duplicity: nothing more is anchored.
	forked := mintedOwnerOf(t, s, machineKindIndividual)
	if err := s.DataStore.MarkMachineOwnerIdentityDuplicitous(forked, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.anchorInOwnerLog(forked, aMachine, 0, aMachine); !errors.Is(err, store.ErrOwnerIdentityDuplicitous) {
		t.Fatalf("a duplicitous owner identity anchored: %v", err)
	}
}

// A running core extends no owner log yet: nothing can ask an owner
// identity's witnesses for their copy of its log, so the writer refuses
// before it reserves or signs anything. This is the case that refusal is
// for: an owner identity minted, the database backed up, a machine anchored,
// the database replaced by the backup and the core started again, and a
// second machine anchored. Neither anchor is made, and the log holds one
// event in every copy. A reservation left waiting in a database is not
// finished at start either.
func TestARunningCoreRefusesToExtendAnOwnerLogUntilItsWitnessesCanBeAsked(t *testing.T) {
	s := adoptingOwner(t)
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	backup := backupOf(t, s)

	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errOwnerLogWitnessesNotYetAskable) {
		t.Fatalf("a running core anchored a machine without asking the witnesses: %v", err)
	}
	if res, _ := s.DataStore.OwnerLogReservations(owner); len(res) != 0 {
		t.Fatalf("%d places were reserved", len(res))
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 1 {
		t.Fatalf("the kept log has %d events", len(kept))
	}

	restored := restoredFrom(t, s, backup)
	if _, err := restored.anchorInOwnerLog(owner, anotherMachine, 0, anotherMachine); !errors.Is(err, errOwnerLogWitnessesNotYetAskable) {
		t.Fatalf("a core restored from the backup anchored a machine without asking the witnesses: %v", err)
	}
	if kept := keptOwnerLog(t, restored, owner); len(kept) != 1 {
		t.Fatalf("the restored log has %d events", len(kept))
	}

	// A reservation left waiting, as a database restored from elsewhere can
	// hold one: the core starts and does not sign it.
	waiting := withWitnessesStandingIn(adoptingOwner(t))
	other := mintedOwnerOf(t, waiting, machineKindIndividual)
	waiting.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := waiting.anchorInOwnerLog(other, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	waiting.ownerLog.witnesses = nil
	started := restartedOver(t, waiting)
	if kept := keptOwnerLog(t, started, other); len(kept) != 1 {
		t.Fatalf("a running core finished a reservation without asking the witnesses: %d kept", len(kept))
	}
	if res, _ := started.DataStore.OwnerLogReservations(other); len(res) != 1 || res[0].State != store.OwnerLogReserved {
		t.Fatalf("the reservation is %+v", res)
	}
}

// Why the writer needs the witnesses: a reservation is a row in one
// database, and a copy of the device restored from an older backup has no
// row for a place this device already used. With witnesses that check
// nothing standing in, the restored copy signs a second, different event at
// that place, and both are validly signed: duplicity.
func TestACopyRestoredFromAnOlderBackupSignsASecondEventAtAPlaceTheReservationOnlyHeldInOneDatabase(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	backup := backupOf(t, s)

	first, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
	if err != nil || first.SN != 1 {
		t.Fatalf("the first anchor: %+v, %v", first, err)
	}
	keptOwnerLog(t, s, owner)

	restored := restoredFrom(t, s, backup)
	second, err := restored.anchorInOwnerLog(owner, anotherMachine, 0, anotherMachine)
	if err != nil {
		t.Fatalf("the restored copy did not anchor: %v", err)
	}
	keptOwnerLog(t, restored, owner)
	if second.SN != first.SN || second.SAID == first.SAID {
		t.Fatalf("the restored copy signed %s at %d, and the first %s at %d: expected two events at one place",
			second.SAID, second.SN, first.SAID, first.SN)
	}
}

// theWriterAllows grants the one signing the writer grants before it signs
// r's bytes, so a test can ask the signer what it would do for the writer.
func theWriterAllows(s *CoreServer, r store.OwnerLogReservation) {
	s.ownerLog.permits.Store(r.OwnerAID, ownerLogPermit{sn: r.SN, digest: r.Digest})
}

// installsAnEventOfAnotherCopy keeps, in to's database at the event's
// place, an event the same owner identity signed in another copy of the
// database: what a restore that brings in a log extended elsewhere leaves.
func installsAnEventOfAnotherCopy(t *testing.T, to *CoreServer, ev store.EventRecord) {
	t.Helper()
	if _, err := to.DataStore.(*store.SQLiteStore).DB().Exec(`DELETE FROM kel WHERE aid = ? AND seq_num >= ?`,
		ev.AID, ev.SequenceNumber); err != nil {
		t.Fatal(err)
	}
	if err := to.DataStore.SaveEvent(ev); err != nil {
		t.Fatal(err)
	}
}

// eventSignedElsewhere is the event at sequence number 1 of owner's log as a
// copy restored from backup signs it, anchoring anotherMachine.
func eventSignedElsewhere(t *testing.T, s *CoreServer, owner, backup string) store.EventRecord {
	t.Helper()
	elsewhere := restoredFrom(t, s, backup)
	if _, err := elsewhere.anchorInOwnerLog(owner, anotherMachine, 0, anotherMachine); err != nil {
		t.Fatal(err)
	}
	return keptOwnerLog(t, elsewhere, owner)[1]
}

// Bytes reserved at a place where the kept log now holds a different event
// are never signed, at start or when asked: two events are known at that
// place, so the owner identity is recorded as duplicitous there.
func TestReservedBytesAreNotSignedWhereTheKeptLogHoldsAnotherEventAtTheirPlace(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	backup := backupOf(t, s)

	// This copy reserves place 1 and stops before signing.
	s.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	s.ownerLog.stopAt = nil
	reserved, _ := s.DataStore.OwnerLogReservations(owner)
	// And the log comes to hold, at place 1, an event signed elsewhere.
	elsewhere := eventSignedElsewhere(t, s, owner, backup)
	installsAnEventOfAnotherCopy(t, s, elsewhere)

	s = restartedOver(t, s)
	raw, _ := base64.StdEncoding.DecodeString(reserved[0].RawB64)
	// Asked as the writer asks, so what refuses is the kept log.
	theWriterAllows(s, reserved[0])
	if sig, err := s.signEventFor(owner, "", raw); err == nil || sig != "" {
		t.Fatalf("bytes reserved where another event is kept were signed: %q", sig)
	}
	kept := keptOwnerLog(t, s, owner)
	if len(kept) != 2 || kept[1].RawBytesB64 != elsewhere.RawBytesB64 {
		t.Fatal("the kept log changed")
	}
	if res, _ := s.DataStore.OwnerLogReservations(owner); len(res) != 1 || res[0].State != store.OwnerLogReserved {
		t.Fatalf("the reservation is %+v", res)
	}
	id, _, _ := s.DataStore.MachineOwnerIdentity(owner)
	if id.DuplicitousAt == nil || *id.DuplicitousAt != 1 {
		t.Fatalf("two events known at place 1 were not recorded as duplicity: %v", id.DuplicitousAt)
	}
}

// Bytes reserved after an event the kept log no longer holds are never
// signed, and the reservation stays, so nothing more is signed in that log.
// Nothing is known twice at their place, so this is not recorded as
// duplicity.
func TestReservedBytesAreNotSignedWhenTheEventTheyFollowIsNoLongerTheKeptTip(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	backup := backupOf(t, s)

	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err != nil {
		t.Fatal(err)
	}
	// Place 2 is reserved after the event at 1, and nothing signed.
	s.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	s.ownerLog.stopAt = nil
	reserved, _ := s.DataStore.OwnerLogReservations(owner)
	waiting := reserved[len(reserved)-1]
	if waiting.SN != 2 || waiting.State != store.OwnerLogReserved {
		t.Fatalf("the reservations are %+v", reserved)
	}
	// The kept log comes to hold, at place 1, an event signed elsewhere.
	installsAnEventOfAnotherCopy(t, s, eventSignedElsewhere(t, s, owner, backup))

	s = restartedOver(t, s)
	raw, _ := base64.StdEncoding.DecodeString(waiting.RawB64)
	theWriterAllows(s, waiting)
	sig, err := s.signEventFor(owner, "", raw)
	if err == nil || sig != "" {
		t.Fatalf("bytes reserved after an event the kept log no longer holds were signed: %q", sig)
	}
	if !errors.Is(err, errOwnerLogCannotBeExtended) || !strings.Contains(err.Error(), "sequence number 2") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 2 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	id, _, _ := s.DataStore.MachineOwnerIdentity(owner)
	if id.DuplicitousAt != nil {
		t.Fatalf("recorded as duplicity at %d, where only one event is known", *id.DuplicitousAt)
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 1, aMachinesRotation); err == nil {
		t.Fatal("the log was extended past a reservation that does not follow it")
	}
}

// Where the record of owner identities cannot be read, the engine's signer
// says so and signs nothing: it does not go on to find a seed some other
// way for an identity that may be an owner identity.
func TestTheSignerSignsNothingWhenTheRecordOfOwnerIdentitiesCannotBeRead(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	if _, err := s.DataStore.(*store.SQLiteStore).DB().Exec(
		`ALTER TABLE machine_owner_identities RENAME TO unreadable_owner_identities`); err != nil {
		t.Fatal(err)
	}
	sig, err := s.signEventFor(owner, "", []byte("an event"))
	if err == nil || sig != "" {
		t.Fatalf("signed with the record unreadable: %q", sig)
	}
	if !strings.Contains(err.Error(), "could not read the machine owner identity") {
		t.Fatalf("the error is not the store's: %v", err)
	}
}

// aReservationLeftWaiting is a core started, as a running core is, over a
// database holding a reservation at place 1 of an owner identity's log whose
// event was never signed. It returns the core, the owner identity and the
// name the engine holds its log under.
func aReservationLeftWaiting(t *testing.T) (*CoreServer, string, string) {
	t.Helper()
	waiting := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, waiting, machineKindIndividual)
	waiting.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := waiting.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	waiting.ownerLog.witnesses = nil
	started := restartedOver(t, waiting)
	name, held, err := started.KeriDriver.(ownerLogEngine).NameHolding(owner)
	if err != nil || !held {
		t.Fatalf("the engine does not hold the owner identity's log: %v", err)
	}
	return started, owner, name
}

// nothingWasSignedIn checks that owner's log is still its founding alone, in
// the store and in the engine, with its reservation still waiting.
func nothingWasSignedIn(t *testing.T, s *CoreServer, owner, name string) {
	t.Helper()
	if kept := keptOwnerLog(t, s, owner); len(kept) != 1 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
	if kel, _ := s.KeriDriver.GetKel(name); kel == nil || kel.EventCount != 1 {
		t.Fatal("the engine's copy of the log was extended")
	}
	if res, _ := s.DataStore.OwnerLogReservations(owner); len(res) != 1 || res[0].State != store.OwnerLogReserved {
		t.Fatalf("the reservation is %+v", res)
	}
}

// The routes that have the engine build a key event by name extend only this
// Identity Agent's own log. An interaction asked for by an owner identity's
// name, carrying exactly the seal of the event reserved in its log, is
// refused, and so is a rotation of it.
func TestTheRoutesThatBuildAKeyEventByNameRefuseAnOwnerIdentitysLog(t *testing.T) {
	s, owner, name := aReservationLeftWaiting(t)

	for _, asked := range []string{name, owner} {
		body, _ := json.Marshal(map[string]any{"name": asked,
			"data": []any{map[string]string{"i": aMachine, "s": "0", "d": aMachine}}})
		rec := httptest.NewRecorder()
		s.handleInteract(rec, httptest.NewRequest(http.MethodPost, "/interact", strings.NewReader(string(body))))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not this Identity Agent's identity") {
			t.Fatalf("an interaction of an owner identity's log was answered %d %s", rec.Code, rec.Body.String())
		}
		k1, k2 := testRotationKeys(t)
		body, _ = json.Marshal(map[string]any{"name": asked, "new_public_key": k1, "new_next_public_key": k2})
		rec = httptest.NewRecorder()
		s.handleRotation(rec, httptest.NewRequest(http.MethodPost, "/rotation", strings.NewReader(string(body))))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not this Identity Agent's identity") {
			t.Fatalf("a rotation of an owner identity's log was answered %d %s", rec.Code, rec.Body.String())
		}
	}
	nothingWasSignedIn(t, s, owner, name)
}

// An owner identity's key signs a key event only when its writer asks, after
// the witnesses' copy was checked. The engine asked directly for the very
// event reserved in the log, past every route, gets no signature.
func TestTheSignerRefusesAnOwnerIdentitysKeyEventItsWriterDidNotAsk(t *testing.T) {
	s, owner, name := aReservationLeftWaiting(t)

	seal := map[string]string{"i": aMachine, "s": "0", "d": aMachine}
	if _, err := s.KeriDriver.Interact(name, []interface{}{seal}); err == nil {
		t.Fatal("the engine had the owner identity's key sign an event its writer did not ask for")
	}
	reserved, _ := s.DataStore.OwnerLogReservations(owner)
	raw, _ := base64.StdEncoding.DecodeString(reserved[0].RawB64)
	if sig, err := s.signEventFor(owner, "", raw); !errors.Is(err, errOwnerLogSigningNotPermitted) || sig != "" {
		t.Fatalf("the reserved bytes were signed without the writer: %q, %v", sig, err)
	}
	nothingWasSignedIn(t, s, owner, name)
}

// The storage route writes no row into an owner identity's key log: the
// writer is the one place that log is extended.
func TestTheStorageRouteWritesNoRowIntoAnOwnerIdentitysLog(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	junk := base64.StdEncoding.EncodeToString([]byte(`{"v":"KERI10JSON000000_","t":"ixn","i":"` + owner + `","s":"1"}`))
	body, _ := json.Marshal(map[string]any{"aid": owner, "sequence_number": 1, "event_type": "ixn", "raw_bytes_b64": junk})
	rec := httptest.NewRecorder()
	s.handleStoreEvent(rec, httptest.NewRequest(http.MethodPost, "/store/event", strings.NewReader(string(body))))
	if rec.Code != http.StatusConflict {
		t.Fatalf("a row was written into an owner identity's log: %d %s", rec.Code, rec.Body.String())
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 1 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
}

// Duplicity is two validly signed events at one place (ADR-087 decision 10).
// An unsigned, made-up row kept at a reserved place proves nothing: the
// reserved bytes are not signed, and the owner identity is not recorded as
// duplicitous.
func TestAnUnsignedRowAtAReservedPlaceIsNotTakenForDuplicity(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	s.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	s.ownerLog.stopAt = nil
	// Kept straight into the store, past every route.
	junk := base64.StdEncoding.EncodeToString([]byte(`{"v":"KERI10JSON000000_","t":"ixn","i":"` + owner + `","s":"1"}`))
	if err := s.DataStore.SaveEvent(store.EventRecord{AID: owner, SequenceNumber: 1, EventType: "ixn",
		RawBytesB64: junk}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err == nil {
		t.Fatal("the writer signed at a place an unverified row holds")
	}
	reserved, _ := s.DataStore.OwnerLogReservations(owner)
	raw, _ := base64.StdEncoding.DecodeString(reserved[0].RawB64)
	theWriterAllows(s, reserved[0])
	sig, err := s.signEventFor(owner, "", raw)
	if err == nil || sig != "" {
		t.Fatalf("the reserved bytes were signed: %q", sig)
	}
	if !errors.Is(err, errOwnerLogCannotBeExtended) || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("the refusal does not say the kept log does not verify: %v", err)
	}
	if id, _, _ := s.DataStore.MachineOwnerIdentity(owner); id.DuplicitousAt != nil {
		t.Fatalf("an unsigned row marked the owner identity duplicitous at %d", *id.DuplicitousAt)
	}
	if res, _ := s.DataStore.OwnerLogReservations(owner); res[0].State != store.OwnerLogReserved {
		t.Fatalf("the reservation is %+v", res)
	}
}

// An owner identity whose log holds two events at one place signs no request
// to a machine: the one it will sign, the rotation that replaces it, has no
// route yet (ADR-087 decision 10).
func TestADuplicitousOwnerIdentitySignsNoRequestToAMachine(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	signs := `{"owner_aid":"` + owner + `","method":"GET","path":"/api/identity","for":"` + aMachine + `"}`
	if rec := askToSignAs(t, s, signs); rec.Code != http.StatusOK {
		t.Fatalf("before it is duplicitous it signs: %d %s", rec.Code, rec.Body.String())
	}
	if err := s.DataStore.MarkMachineOwnerIdentityDuplicitous(owner, 1); err != nil {
		t.Fatal(err)
	}
	rec := askToSignAs(t, s, signs)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "two events at one place") {
		t.Fatalf("a duplicitous owner identity signed a request: %d %s", rec.Code, rec.Body.String())
	}
}

// witnessesWhoseQueueFailsOnce stand in for witnesses that agree with the
// kept log and whose queue fails the first time it is asked, then holds each
// event it is asked for once.
type witnessesWhoseQueueFailsOnce struct {
	mu     sync.Mutex
	failed bool
	queued map[int]int
}

func (*witnessesWhoseQueueFailsOnce) continuesFromWhatTheyHold(string, *drivers.DriverKelResponse) error {
	return nil
}

func (w *witnessesWhoseQueueFailsOnce) await(_ string, sn int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.failed {
		w.failed = true
		return errors.New("the queue could not be written")
	}
	if w.queued == nil {
		w.queued = map[int]int{}
	}
	w.queued[sn]++
	return nil
}

func (w *witnessesWhoseQueueFailsOnce) queuedAt(sn int) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.queued[sn]
}

// An event kept and not queued for its witnesses, because the queue failed,
// is queued when the core starts again (ADR-087 decision 12).
func TestAnEventKeptAndNotQueuedIsQueuedWhenTheCoreStarts(t *testing.T) {
	s := adoptingOwner(t)
	witnesses := &witnessesWhoseQueueFailsOnce{}
	s.ownerLog.witnesses = witnesses
	owner := mintedOwnerOf(t, s, machineKindIndividual)

	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err == nil {
		t.Fatal("the queue failed and the writer said nothing")
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 2 || witnesses.queuedAt(1) != 0 {
		t.Fatalf("the kept log has %d events, and the event was queued %d times", len(kept), witnesses.queuedAt(1))
	}
	restartedOver(t, s)
	if witnesses.queuedAt(1) == 0 {
		t.Fatal("the event kept was not queued when the core started again")
	}

	// A core whose witnesses cannot be asked yet starts all the same, and
	// holds the log.
	s.ownerLog.witnesses = nil
	started := restartedOver(t, s)
	if _, _, err := started.heldOwnerLog(owner); err != nil {
		t.Fatalf("the core started without the log: %v", err)
	}
}

// An event kept and not queued is queued when the same anchor is asked for
// again.
func TestAnEventKeptAndNotQueuedIsQueuedWhenItsAnchorIsAskedForAgain(t *testing.T) {
	s := adoptingOwner(t)
	witnesses := &witnessesWhoseQueueFailsOnce{}
	s.ownerLog.witnesses = witnesses
	owner := mintedOwnerOf(t, s, machineKindIndividual)

	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err == nil {
		t.Fatal("the queue failed and the writer said nothing")
	}
	again, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
	if err != nil || again.Written || again.SN != 1 {
		t.Fatalf("asked again: %+v, %v", again, err)
	}
	if witnesses.queuedAt(1) == 0 {
		t.Fatal("the event kept was not queued when its anchor was asked for again")
	}
}

// aStoreThatPanicsWhenAskedForTheIdentity stands in for a store, so that the
// engine's signer, which asks it first, panics.
type aStoreThatPanicsWhenAskedForTheIdentity struct{ store.Store }

func (aStoreThatPanicsWhenAskedForTheIdentity) GetIdentity() (*store.IdentityState, error) {
	panic("the signer stopped")
}

// A signer that panics leaves no permit behind: nothing that runs after the
// panic, which the HTTP server recovers from, can sign as the owner
// identity with it.
func TestASignerThatPanicsLeavesNoPermitBehind(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	s.ownerLog.stopAt = func(at ownerLogStep) error {
		if at == ownerLogReserved {
			return errTheDeviceStopped
		}
		return nil
	}
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); !errors.Is(err, errTheDeviceStopped) {
		t.Fatal(err)
	}
	reserved, err := s.DataStore.OwnerLogReservations(owner)
	if err != nil || len(reserved) != 1 {
		t.Fatalf("the reservations are %+v, %v", reserved, err)
	}
	eng, name, err := s.heldOwnerLog(owner)
	if err != nil {
		t.Fatal(err)
	}

	s.DataStore = aStoreThatPanicsWhenAskedForTheIdentity{s.DataStore}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the signer did not panic")
			}
		}()
		s.signAndKeepReserved(eng, name, reserved[0])
	}()
	if _, held := s.ownerLog.permits.Load(owner); held {
		t.Fatal("a permit to sign as the owner identity was left behind by a signer that panicked")
	}
}

// The copy of an owner log that is served is brought up to the kept log when
// the core starts, as it must be after a restore replaced the kept log, and
// what the core reads from its file afterwards is the kept log too.
func TestTheServedOwnerLogFollowsTheKeptOneWhenTheCoreStarts(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	founding, _ := s.getPairwiseKEL(owner)
	if _, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine); err != nil {
		t.Fatal(err)
	}
	// The served copy as a restore leaves it: the one from before the anchor.
	key, _ := s.getPairwiseKey(owner)
	s.rememberMintedPairwise(owner, key, founding[:1])

	started := restartedOver(t, s)
	// In the order Start runs them: the key logs, then the file.
	started.restoreMintedPairwise()
	if served, _ := started.getPairwiseKEL(owner); len(served) != 2 {
		t.Fatalf("the served copy has %d events and the kept log 2", len(served))
	}
}

// A reservation written into the table by anything but the writer, as a
// restore could leave one, is not signed unless its bytes are the
// interaction it describes and anchor the Identity Agent the owner identity
// is recorded as anchoring. The writer's permit is given, so what refuses is
// the reading of the bytes. The reservation stays, waiting.
func TestTheSignerSignsOnlyAReservationThatIsWhatItSays(t *testing.T) {
	interaction := func(t *testing.T, prefix, prior string, sn int, anchors string) []byte {
		t.Helper()
		seal, err := drivers.EventSeal(anchors, "0", anchors)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: prefix, PriorSAID: prior, SN: sn,
			Data: []json.RawMessage{seal}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	digestOf := func(raw []byte) string {
		d, _ := drivers.EventIDOfRawB64(base64.StdEncoding.EncodeToString(raw))
		return d
	}
	stranger := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	cases := map[string]func(owner string) []byte{
		"another identifier": func(owner string) []byte {
			return interaction(t, stranger.AID, owner, 1, aMachine)
		},
		"another place": func(owner string) []byte {
			return interaction(t, owner, owner, 2, aMachine)
		},
		"a rotation": func(owner string) []byte {
			return []byte(strings.Replace(string(interaction(t, owner, owner, 1, aMachine)), `"t":"ixn"`, `"t":"rot"`, 1))
		},
		"a seal naming another Identity Agent": func(owner string) []byte {
			return interaction(t, owner, owner, 1, anotherMachine)
		},
		"two event seals": func(owner string) []byte {
			first, _ := drivers.EventSeal(aMachine, "0", aMachine)
			second, _ := drivers.EventSeal(aMachine, "1", aMachine)
			raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: owner, PriorSAID: owner, SN: 1,
				Data: []json.RawMessage{first, second}})
			if err != nil {
				t.Fatal(err)
			}
			return raw
		},
		"a digest that is not the digest of its bytes": func(owner string) []byte {
			raw := interaction(t, owner, owner, 1, aMachine)
			return []byte(strings.Replace(string(raw), digestOf(raw), aMachinesRotation, 1))
		},
	}
	// A true anchor with something after it, its digest derived again over
	// the longer bytes.
	for name, tail := range map[string]string{"a newline after the event": "\n",
		"spaces after the event": "   ", "an empty object after the event": "{}", "junk after the event": "junk"} {
		tail := tail
		cases[name] = func(owner string) []byte {
			raw := interaction(t, owner, owner, 1, aMachine)
			padded := append(append([]byte{}, raw...), tail...)
			d, err := keri.ComputeSAID(padded)
			if err != nil {
				t.Fatal(err)
			}
			return []byte(strings.Replace(string(padded), digestOf(raw), d, 1))
		}
	}
	for name, bytesFor := range cases {
		t.Run(name, func(t *testing.T) {
			s := withWitnessesStandingIn(adoptingOwner(t))
			owner := mintedOwnerOf(t, s, machineKindIndividual)
			raw := bytesFor(owner)
			r := store.OwnerLogReservation{OwnerAID: owner, SN: 1, PriorDigest: owner, Digest: digestOf(raw),
				RawB64: base64.StdEncoding.EncodeToString(raw)}
			db := s.DataStore.(*store.SQLiteStore).DB()
			if _, err := db.Exec(`INSERT INTO owner_log_reservations
				(owner_aid, seq_num, prior_digest, digest, event_bytes_b64, state) VALUES (?, ?, ?, ?, ?, 'reserved')`,
				r.OwnerAID, r.SN, r.PriorDigest, r.Digest, r.RawB64); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`UPDATE machine_owner_identities SET anchored_m = ? WHERE aid = ?`, aMachine, owner); err != nil {
				t.Fatal(err)
			}
			theWriterAllows(s, r)
			if sig, err := s.signEventFor(owner, "", raw); err == nil || sig != "" {
				t.Fatalf("bytes that are not what their reservation says were signed: %q", sig)
			}
			if res, _ := s.DataStore.OwnerLogReservations(owner); len(res) != 1 || res[0].State != store.OwnerLogReserved {
				t.Fatalf("the reservation is %+v", res)
			}
		})
	}
}

// An interaction whose data is not exactly one event seal is not an anchor,
// whatever seals it carries: the writer reads the log as the ownership check
// does (ownership.TheAnchorIn). Here the owner identity's log holds, at place
// 1, an interaction carrying the very seal asked for beside a second one. It
// is not taken as the anchor already made, and the anchor is written after
// it.
func TestAnInteractionThatIsNotExactlyOneEventSealIsNotAnAnchor(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	asked, _ := drivers.EventSeal(aMachine, "0", aMachine)
	beside, _ := drivers.EventSeal(aMachine, "1", aMachinesRotation)
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: owner, PriorSAID: owner, SN: 1,
		Data: []json.RawMessage{asked, beside}})
	if err != nil {
		t.Fatal(err)
	}
	id, _, _ := s.DataStore.MachineOwnerIdentity(owner)
	seed, err := s.pairwiseSigningSeed(id.KeyIndex)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signEventBytes(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := eventRecordOf(owner, 1, raw, []string{sig})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveEvent(rec); err != nil {
		t.Fatal(err)
	}
	keptOwnerLog(t, s, owner)

	ev, err := s.anchorInOwnerLog(owner, aMachine, 0, aMachine)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Written || ev.SN != 2 {
		t.Fatalf("an interaction with two event seals was taken as the anchor: written=%v at %d", ev.Written, ev.SN)
	}
	if kept := keptOwnerLog(t, s, owner); len(kept) != 3 {
		t.Fatalf("the kept log has %d events", len(kept))
	}
}

// The signer signs a reservation only for an owner identity recorded as
// anchoring the Identity Agent it anchors. A place is reserved only together
// with recording one, so a reservation beside a record that names none is
// not signed. The same reservation, with the record naming that Identity
// Agent, is.
func TestTheSignerSignsNoReservationForAnOwnerIdentityRecordedAsAnchoringNothing(t *testing.T) {
	s := withWitnessesStandingIn(adoptingOwner(t))
	owner := mintedOwnerOf(t, s, machineKindIndividual)
	seal, _ := drivers.EventSeal(aMachine, "0", aMachine)
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: owner, PriorSAID: owner, SN: 1,
		Data: []json.RawMessage{seal}})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := drivers.EventIDOfRawB64(base64.StdEncoding.EncodeToString(raw))
	r := store.OwnerLogReservation{OwnerAID: owner, SN: 1, PriorDigest: owner, Digest: d,
		RawB64: base64.StdEncoding.EncodeToString(raw)}
	db := s.DataStore.(*store.SQLiteStore).DB()
	if _, err := db.Exec(`INSERT INTO owner_log_reservations
		(owner_aid, seq_num, prior_digest, digest, event_bytes_b64, state) VALUES (?, ?, ?, ?, ?, 'reserved')`,
		r.OwnerAID, r.SN, r.PriorDigest, r.Digest, r.RawB64); err != nil {
		t.Fatal(err)
	}

	theWriterAllows(s, r)
	if sig, err := s.signEventFor(owner, "", raw); err == nil || sig != "" {
		t.Fatalf("a reservation was signed for an owner identity recorded as anchoring nothing: %q", sig)
	}
	if _, err := db.Exec(`UPDATE machine_owner_identities SET anchored_m = ? WHERE aid = ?`, aMachine, owner); err != nil {
		t.Fatal(err)
	}
	theWriterAllows(s, r)
	if sig, err := s.signEventFor(owner, "", raw); err != nil || sig == "" {
		t.Fatalf("with the record naming the Identity Agent it anchors, it was not signed: %v", err)
	}
}
