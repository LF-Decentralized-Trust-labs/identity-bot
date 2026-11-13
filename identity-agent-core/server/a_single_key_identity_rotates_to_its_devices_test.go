package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// Can an identity founded with ONE key (the sealed box's own) rotate so
// that device members control it and the box's key is in neither the signing
// set nor the next set?
//
// The box and each device are test doubles here: an Ed25519 seed that signs
// what it is shown, through the same prepare and commit routes an app uses.
// What is under test is the key event log, which does not care who holds a key,
// and keripy's judgement of it.
//
// The sequence that is proved:
//
//	icp   box key B0, commits to box key B1                         (the box's founding)
//	rot1  signed by B1 (opens the commitment) + devices A0, C0;
//	      commits ONLY to the devices' next keys A1, C1             (the hand-over)
//	rot2  signed by A1 + C1 alone; commits to A2, C2                (the box is gone)
//
// Two rotations, not one, because the founding committed to the box's key and
// nothing else: rot1 has to reveal and be signed by it.

// aSigner is a test double for a key holder.
type aSigner struct{ seed []byte }

func (k aSigner) key() string { return verkeyOf(k.seed) }

// at signs raw as the key sitting at place of the event's own key list. prior is
// the place its digest holds in the previous event's next list, or -1 when the
// key was not committed to there (a member joining), which signs current-only.
func (k aSigner) at(t *testing.T, raw []byte, index, prior int) string {
	t.Helper()
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(k.seed), raw)
	place := keri.SignaturePlace{Index: index, Ondex: prior}
	if prior < 0 {
		place = keri.SignaturePlace{Index: index, CurrentOnly: true}
	}
	q, err := keri.EncodeIndexedSignature(sig, place)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func signerSeeds(n, from int) []aSigner {
	seeds := appSeeds(from + n)
	out := make([]aSigner, n)
	for i := range out {
		out[i] = aSigner{seeds[from+i]}
	}
	return out
}

func verkeysOf(ks ...aSigner) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.key()
	}
	return out
}

func digestsOfSigners(t *testing.T, ks ...aSigner) []string {
	t.Helper()
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = digestOfSeed(t, k.seed)
	}
	return out
}

// prepared asks the core to build a rotation or interaction and returns its bytes.
func prepareRaw(t *testing.T, s *CoreServer, req map[string]any) (raw []byte, code int, out map[string]any) {
	t.Helper()
	code, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", req)
	if code != http.StatusOK {
		return nil, code, out
	}
	return preparedBytes(t, out), code, out
}

func commitWith(t *testing.T, s *CoreServer, raw []byte, sigs ...string) (int, map[string]any) {
	t.Helper()
	return call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": b64s(raw), "sigs": sigs})
}

// aHandedOverIdentity is a box identity after rot1, and rot2 when it could be made.
type aHandedOverIdentity struct {
	s           *CoreServer
	aid         string
	box         []aSigner // B0 the inception key, B1 revealed in rot1, B2 committed in rot1 when asked
	a, c        []aSigner // the two devices: key now, next, the one after
	rot1, rot2  []byte
	tip1, tip2  map[string]string
	rot2Code    int
	rot2Out     map[string]any
	rot2Waiting bool
}

// handOver founds a box identity with one key and carries out rot1, then tries
// rot2 signed by the two devices alone. commitBoxNext says whether rot1 also
// commits to a next key of the box's, which is what handleStartCeremony does
// today (its next set is the box's next key plus each device's).
func handOverBox(t *testing.T, commitBoxNext bool) *aHandedOverIdentity {
	t.Helper()
	s := appHeldCore(t)
	h := &aHandedOverIdentity{s: s, box: signerSeeds(3, 0), a: signerSeeds(3, 10), c: signerSeeds(3, 20)}
	box, a, c := h.box, h.a, h.c

	// Founding: one key and one commitment, the box's.
	icp, code, out := prepareRaw(t, s, map[string]any{
		"t": "icp", "k": verkeysOf(box[0]), "kt": "1", "n": digestsOfSigners(t, box[1]), "nt": "1"})
	if code != http.StatusOK {
		t.Fatalf("prepare founding: %d %v", code, out)
	}
	if code, res := commitWith(t, s, icp, box[0].at(t, icp, 0, 0)); code != http.StatusCreated {
		t.Fatalf("founding: %d %v", code, res)
	}
	own, _ := s.DataStore.GetIdentity()
	h.aid = own.AID

	// rot1 reveals the box's committed key B1 (first, as the engine requires), adds
	// both devices, and commits to what controls the identity next.
	next, nt := digestsOfSigners(t, a[1], c[1]), "2"
	if commitBoxNext {
		next, nt = digestsOfSigners(t, box[2], a[1], c[1]), "3"
	}
	seals := []any{}
	for _, owner := range []string{"EDeviceAPairwiseAID000000000000000000000000", "EDeviceCPairwiseAID000000000000000000000000"} {
		seal, err := ownerAnchorSeal(owner)
		if err != nil {
			t.Fatal(err)
		}
		seals = append(seals, seal)
	}
	var raw1 []byte
	raw1, code, out = prepareRaw(t, s, map[string]any{"aid": h.aid, "t": "rot",
		"k": verkeysOf(box[1], a[0], c[0]), "kt": "3", "n": next, "nt": nt, "a": seals,
		"after": map[string]string{"s": "0", "d": h.aid}})
	if code != http.StatusOK {
		t.Fatalf("prepare rot1: %d %v", code, out)
	}
	h.rot1 = raw1
	// The box signs first; the devices have not yet: the core holds it.
	code, res := commitWith(t, s, raw1, box[1].at(t, raw1, 0, 0))
	if code != http.StatusAccepted || res["status"] != "waiting_for_signatures" {
		t.Fatalf("rot1 signed by the box alone should wait for the devices: %d %v", code, res)
	}
	code, res = commitWith(t, s, raw1, a[0].at(t, raw1, 1, -1), c[0].at(t, raw1, 2, -1))
	if code != http.StatusCreated {
		t.Fatalf("rot1 with every signer: %d %v", code, res)
	}
	h.tip1 = map[string]string{"s": "1", "d": res["d"].(string)}

	// rot2: the devices' next keys, which rot1 committed to, alone. The first
	// two places of the committed list are the devices' in the box-dropped
	// case and the second and third when the box's was committed too.
	priorA, priorC := 0, 1
	if commitBoxNext {
		priorA, priorC = 1, 2
	}
	raw2, code, out := prepareRaw(t, s, map[string]any{"aid": h.aid, "t": "rot",
		"k": verkeysOf(a[1], c[1]), "kt": "2", "n": digestsOfSigners(t, a[2], c[2]), "nt": "2",
		"after": h.tip1})
	if code != http.StatusOK {
		// Refused before anybody is asked to sign: the keys cannot open the commitment.
		h.rot2Code, h.rot2Out = code, out
		return h
	}
	h.rot2 = raw2
	code, res = commitWith(t, s, raw2, a[1].at(t, raw2, 0, priorA), c[1].at(t, raw2, 1, priorC))
	h.rot2Code, h.rot2Out = code, res
	if code == http.StatusCreated {
		h.tip2 = map[string]string{"s": "2", "d": res["d"].(string)}
	}
	return h
}

// The hand-over works: two rotations take a one-key box identity to two
// devices, and the box's keys are in neither the signing nor the next set.
func TestAOneKeyBoxIdentityRotatesToItsDevicesAndDropsTheBoxKey(t *testing.T) {
	keripyCases = nil
	h := handOverBox(t, false)
	if h.rot2Code != http.StatusCreated {
		t.Fatalf("rot2, signed by the devices alone: %d %v", h.rot2Code, h.rot2Out)
	}
	ev1, _ := keri.ParseEvent(h.rot1)
	ev2, _ := keri.ParseEvent(h.rot2)
	box := map[string]bool{}
	boxDigest := map[string]bool{}
	for _, b := range h.box {
		box[b.key()] = true
		d, _ := keri.NextDigest(b.key())
		boxDigest[d] = true
	}
	for _, k := range ev1.Keys[1:] {
		if box[k] {
			t.Errorf("rot1 lists a box key beyond the one it must reveal")
		}
	}
	for _, d := range ev1.NextDigest {
		if boxDigest[d] {
			t.Errorf("rot1 still commits to a box key: the box could be asked to sign the next rotation")
		}
	}
	for _, k := range ev2.Keys {
		if box[k] {
			t.Errorf("rot2 is signed by a box key")
		}
	}
	for _, d := range ev2.NextDigest {
		if boxDigest[d] {
			t.Errorf("rot2 commits to a box key")
		}
	}
	if ev2.Keys[0] != h.a[1].key() || ev2.Keys[1] != h.c[1].key() || len(ev2.Keys) != 2 {
		t.Errorf("rot2's signing set is %v, want the two devices", ev2.Keys)
	}

	// After the hand-over: the devices extend the log, the box's old keys cannot.
	ixn, code, out := prepareRaw(t, h.s, map[string]any{"aid": h.aid, "t": "ixn",
		"a": []any{map[string]string{"d": "EAnchoredByTheDevices"}}, "after": h.tip2})
	if code != http.StatusOK {
		t.Fatalf("prepare ixn: %d %v", code, out)
	}
	current := func(k aSigner, i int) string { return k.at(t, ixn, i, -2) }
	_ = current
	boxSig := keri.SignaturePlace{Index: 0, CurrentOnly: true}
	q, _ := keri.EncodeIndexedSignature(ed25519.Sign(ed25519.NewKeyFromSeed(h.box[1].seed), ixn), boxSig)
	if code, res := commitWith(t, h.s, ixn, q); code == http.StatusCreated {
		t.Fatalf("an interaction signed by the box's key was accepted after the hand-over: %v", res)
	}
	sig := func(k aSigner, i int) string {
		q, err := keri.EncodeIndexedSignature(ed25519.Sign(ed25519.NewKeyFromSeed(k.seed), ixn),
			keri.SignaturePlace{Index: i, CurrentOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	if code, res := commitWith(t, h.s, ixn, sig(h.a[1], 0), sig(h.c[1], 1)); code != http.StatusCreated {
		t.Fatalf("an interaction signed by both devices after the hand-over: %d %v", code, res)
	}

	m, last := storedLog(t, h.s, h.aid)
	record(t, "box-to-devices", "a one-key box identity: its founding, a rotation that reveals the box's committed key and "+
		"adds two devices while committing only to the devices, then a rotation signed by the devices alone, then an interaction", m, last)
	if out := os.Getenv("IDENTITY_BOT_INTEROP_OUT"); out != "" {
		b, _ := jsonIndent(keripyCases)
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// What the ceremony commits to today cannot hand over: while rot1 commits to a
// box key at threshold "all", a rotation without the box's key is refused, so
// the box key stays in control for good.
func TestACeremonyThatCommitsToTheBoxKeyCannotDropIt(t *testing.T) {
	h := handOverBox(t, true)
	if h.rot2Code == http.StatusCreated {
		t.Fatal("the devices dropped a box key the previous rotation still committed to")
	}
	t.Logf("rot2 without the box key, after a rot1 that commits to it: %d %v", h.rot2Code, h.rot2Out)
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", " ") }

// The ceremony's own call cannot do it either: RotateToMultisig signs only with
// keys this core holds, and a device's key is never here, so a rotation that
// needs a device's signature is refused and the ceremony ends "failed".
func TestTheCeremonysRotationNeedsSignaturesOnlyTheDevicesCanMake(t *testing.T) {
	s := appHeldCore(t)
	box, a := signerSeeds(2, 0), signerSeeds(2, 10)
	icp, code, out := prepareRaw(t, s, map[string]any{
		"t": "icp", "k": verkeysOf(box[0]), "kt": "1", "n": digestsOfSigners(t, box[1]), "nt": "1"})
	if code != http.StatusOK {
		t.Fatalf("prepare founding: %d %v", code, out)
	}
	if code, res := commitWith(t, s, icp, box[0].at(t, icp, 0, 0)); code != http.StatusCreated {
		t.Fatalf("founding: %d %v", code, res)
	}
	own, _ := s.DataStore.GetIdentity()
	// The box's own signer is installed, as it is on a box that holds its key.
	s.eventSigners.Store(own.AID, box[1].seed)
	_, err := s.KeriDriver.RotateToMultisig(own.AID, verkeysOf(box[1], a[0]), digestsOfSigners(t, box[0], a[1]), "2", "2", nil)
	if err == nil {
		t.Fatal("a two-of-two rotation was made without the device's signature")
	}
	t.Logf("RotateToMultisig with a device member, as the ceremony calls it: %v", err)
}
