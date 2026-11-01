package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/recovery"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// appSeeds stand in for the app's keys: derived where the app derives them
// and never given to the core.
func appSeeds(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		seed := make([]byte, 32)
		seed[0], seed[1] = 0xA9, byte(i+1)
		out[i] = seed
	}
	return out
}

func verkeyOf(seed []byte) string {
	return iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func digestOfSeed(t *testing.T, seed []byte) string {
	t.Helper()
	d, err := keri.NextDigest(verkeyOf(seed))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// appSign is the app's indexed signature over raw: index 0 opening the prior
// commitment's first place, or (ixn) current-only.
func appSign(t *testing.T, seed, raw []byte, opens bool) string {
	t.Helper()
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), raw)
	at := keri.SamePlace(0)
	if !opens {
		at = keri.SignaturePlace{Index: 0, CurrentOnly: true}
	}
	qb64, err := keri.EncodeIndexedSignature(sig, at)
	if err != nil {
		t.Fatal(err)
	}
	return qb64
}

func appHeldCore(t *testing.T) *CoreServer {
	t.Helper()
	aMachineThatMayFound(t)
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub(),
		KeriDriver: keriengine.New()}
	endsItsBackgroundWork(t, s)
	s.engineSigns()
	return s
}

func call(t *testing.T, s *CoreServer, h http.HandlerFunc, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, ownerRequest(http.MethodPost, path, strings.NewReader(string(b)), s))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func preparedBytes(t *testing.T, out map[string]any) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(out["raw_b64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// An identity whose key the app holds is founded, rotated and extended
// through prepare and commit. Nothing is stored until it is signed, a wrong
// signature writes nothing, and after a restart the stored log, signatures
// and all, verifies and is extended.
func TestAnAppHeldIdentityIsFoundedRotatedAndExtendedThroughTheCore(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(3)

	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	if code != http.StatusOK {
		t.Fatalf("prepare founding: %d %v", code, out)
	}
	icp := preparedBytes(t, out)
	if own, _ := s.DataStore.GetIdentity(); own != nil {
		t.Fatal("preparing a founding stored an identity")
	}
	code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}})
	if code != http.StatusCreated {
		t.Fatalf("commit founding: %d %v", code, out)
	}
	own, _ := s.DataStore.GetIdentity()
	if own == nil {
		t.Fatal("the founding was not recorded")
	}
	aid := own.AID

	// A rotation names the event it follows.
	rot := map[string]any{"aid": aid, "t": "rot", "k": []string{verkeyOf(k[1])}, "kt": "1",
		"n": []string{digestOfSeed(t, k[2])}, "nt": "1"}
	if code, _ := call(t, s, s.handlePrepareEvent, "/api/events/prepare", rot); code != http.StatusBadRequest {
		t.Fatalf("a rotation prepared with no after: %d", code)
	}
	rot["after"] = map[string]string{"s": "0", "d": aid}
	code, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", rot)
	if code != http.StatusOK {
		t.Fatalf("prepare rotation: %d %v", code, out)
	}
	rotRaw := preparedBytes(t, out)

	code, _ = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(rotRaw), "sigs": []string{appSign(t, k[0], rotRaw, true)}})
	if code != http.StatusBadRequest {
		t.Fatalf("a rotation signed by the key it rotates away from: %d", code)
	}
	if evs, _ := s.DataStore.GetEvents(aid); len(evs) != 1 {
		t.Fatalf("a refused commit stored something: %d events", len(evs))
	}
	code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(rotRaw), "sigs": []string{appSign(t, k[1], rotRaw, true)}})
	if code != http.StatusCreated {
		t.Fatalf("commit rotation: %d %v", code, out)
	}
	rotSAID := out["d"].(string)

	// Restart: a fresh engine reloaded from the store.
	s.KeriDriver = keriengine.New()
	s.reloadIdentityIntoDriver()

	code, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"aid": aid, "t": "ixn", "a": []any{map[string]string{"d": "EAnchoredAfterARestart"}},
		"after": map[string]string{"s": "1", "d": rotSAID}})
	if code != http.StatusOK {
		t.Fatalf("prepare interaction after a restart: %d %v", code, out)
	}
	ixn := preparedBytes(t, out)
	code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(ixn), "sigs": []string{appSign(t, k[1], ixn, false)}})
	if code != http.StatusCreated {
		t.Fatalf("commit interaction after a restart: %d %v", code, out)
	}

	evs, _ := s.DataStore.GetEvents(aid)
	var messages [][]byte
	for _, ev := range evs {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		group, err := keri.AttachControllerSigs(ev.ControllerSignatures())
		if err != nil {
			t.Fatalf("event %d is stored without its signatures", ev.SequenceNumber)
		}
		messages = append(messages, append(raw, group...))
	}
	if _, err := keri.ValidateSignedKEL(messages); err != nil {
		t.Fatalf("the stored log does not verify: %v", err)
	}
}

// A commit on a tip that has moved is answered with the tip, and a rotation to
// a key nobody committed to is refused before anybody signs it.
func TestTheCoreSaysWhyItRefusesAnEvent(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(4)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	icp := preparedBytes(t, out)
	call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}})
	own, _ := s.DataStore.GetIdentity()
	after := map[string]string{"s": "0", "d": own.AID}

	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID,
		"t": "rot", "k": []string{verkeyOf(k[2])}, "kt": "1", "n": []string{digestOfSeed(t, k[3])}, "nt": "1", "after": after})
	if code != http.StatusUnprocessableEntity || out["error"] != "not_committed" {
		t.Fatalf("a rotation to an uncommitted key: %d %v", code, out)
	}

	prep := func(d string) []byte {
		_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID,
			"t": "ixn", "a": []any{map[string]string{"d": d}}, "after": after})
		return preparedBytes(t, out)
	}
	a, b := prep("EA"), prep("EB")
	call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(a), "sigs": []string{appSign(t, k[0], a, false)}})
	code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(b), "sigs": []string{appSign(t, k[0], b, false)}})
	tip, _ := out["tip"].(map[string]any)
	if code != http.StatusConflict || out["error"] != "tip_moved" || tip["s"] != "1" {
		t.Fatalf("a commit on a moved tip: %d %v", code, out)
	}
}

// The routes are the owner's, and closed to a controller at any score.
func TestKeyEventRoutesAreTheOwnersAlone(t *testing.T) {
	for _, route := range []string{"POST /api/events/prepare", "POST /api/events/commit"} {
		if _, ok := controllerOwnerOnly[route]; !ok {
			t.Errorf("%s is open to a controller", route)
		}
	}
	s := appHeldCore(t)
	rec := httptest.NewRecorder()
	s.handlePrepareEvent(rec, remote(http.MethodPost, "/api/events/prepare", `{"t":"icp"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a caller who is not the owner prepared an event: %d", rec.Code)
	}
}

// A core that holds the identity's key founds and rotates it through its own
// routes, and every event it stores carries the signature it was added with:
// the stored log verifies, which it did not while rotations were appended
// unsigned.
func TestACoreHeldRotationIsStoredSigned(t *testing.T) {
	aMachineThatMayFound(t)
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub(),
		KeriDriver: keriengine.New()}
	endsItsBackgroundWork(t, s)
	s.engineSigns()
	root, err := ensureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := func(gen int) string {
		seed, err := backup.DerivePairwiseSeed(root, 0, gen)
		if err != nil {
			t.Fatal(err)
		}
		return verkeyOf(seed)
	}

	code, out := call(t, s, s.handleInception, "/api/inception",
		map[string]any{"public_key": key(0), "next_public_key": key(1)})
	if code != http.StatusCreated {
		t.Fatalf("founding: %d %v", code, out)
	}
	aid := out["aid"].(string)
	code, out = call(t, s, s.handleRotation, "/api/rotation",
		map[string]any{"name": aid, "new_public_key": key(1), "new_next_public_key": key(2)})
	if code != http.StatusOK {
		t.Fatalf("rotation: %d %v", code, out)
	}

	code, out = call(t, s, s.handleRotation, "/api/rotation",
		map[string]any{"name": aid, "new_public_key": key(2), "new_next_public_key": key(3)})
	if code != http.StatusOK {
		t.Fatalf("a second rotation: %d %v", code, out)
	}

	evs, _ := s.DataStore.GetEvents(aid)
	if len(evs) != 3 {
		t.Fatalf("%d events stored", len(evs))
	}
	var messages [][]byte
	for _, ev := range evs {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		group, err := keri.AttachControllerSigs(ev.ControllerSignatures())
		if err != nil {
			t.Fatalf("event %d (%s) is stored without its signature", ev.SequenceNumber, ev.EventType)
		}
		messages = append(messages, append(raw, group...))
	}
	if _, err := keri.ValidateSignedKEL(messages); err != nil {
		t.Fatalf("the stored log does not verify: %v", err)
	}
}

// A recovery rotation the app prepared and signed, following an interaction
// it keeps, supersedes the interactions after it: in the engine and in the
// store, where they are moved aside rather than deleted, and the log that
// remains verifies.
func TestARecoveryRotationSupersedesWhatAThiefAnchored(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(3)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	icp := preparedBytes(t, out)
	call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}})
	own, _ := s.DataStore.GetIdentity()
	after := map[string]string{"s": "0", "d": own.AID}
	var kept map[string]string
	for i, d := range []string{"EKeptByTheOwner", "EAnchoredByAThief", "EAlsoByTheThief"} {
		_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID,
			"t": "ixn", "a": []any{map[string]string{"d": d}}, "after": after})
		raw := preparedBytes(t, out)
		code, res := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
			"raw_b64": base64.StdEncoding.EncodeToString(raw), "sigs": []string{appSign(t, k[0], raw, false)}})
		if code != http.StatusCreated {
			t.Fatalf("interaction %d: %d %v", i, code, res)
		}
		after = map[string]string{"s": res["s"].(string), "d": res["d"].(string)}
		if i == 0 {
			kept = after
		}
	}

	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID,
		"t": "rot", "k": []string{verkeyOf(k[1])}, "kt": "1", "n": []string{digestOfSeed(t, k[2])}, "nt": "1",
		"after": kept})
	if code != http.StatusOK {
		t.Fatalf("prepare recovery rotation: %d %v", code, out)
	}
	rot := preparedBytes(t, out)
	rec := httptest.NewRecorder()
	res, ok := s.commitRecoveryRotation(rec, recovery.RotationRequest{
		RawB64: base64.StdEncoding.EncodeToString(rot), Sigs: []string{appSign(t, k[1], rot, true)}})
	if !ok {
		t.Fatalf("the recovery rotation was refused: %d %s", rec.Code, rec.Body.String())
	}
	if res.SequenceNumber != 2 {
		t.Fatalf("the recovery rotation is at %d, not just after the kept interaction", res.SequenceNumber)
	}
	evs, _ := s.DataStore.GetEvents(own.AID)
	aside, _ := s.DataStore.SupersededEvents(own.AID)
	if len(evs) != 3 || len(aside) != 2 {
		t.Fatalf("the log holds %d events and %d were set aside; want 3 and 2", len(evs), len(aside))
	}
	if !strings.Contains(aside[0].EventJSON, "EAnchoredByAThief") {
		t.Fatalf("the wrong interaction was set aside: %s", aside[0].EventJSON)
	}
	var messages [][]byte
	for _, ev := range evs {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		group, err := keri.AttachControllerSigs(ev.ControllerSignatures())
		if err != nil {
			t.Fatalf("event %d is stored without its signatures", ev.SequenceNumber)
		}
		messages = append(messages, append(raw, group...))
	}
	if _, err := keri.ValidateSignedKEL(messages); err != nil {
		t.Fatalf("the recovered log does not verify: %v", err)
	}
}

// A founding that pairs this Identity Agent's key with somebody else's next key
// is not signed here: the next rotation would belong to whoever holds that
// next key.
func TestAFoundingWithAForeignNextKeyIsNotSignedHere(t *testing.T) {
	aMachineThatMayFound(t)
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub(),
		KeriDriver: keriengine.New()}
	endsItsBackgroundWork(t, s)
	s.engineSigns()
	root, err := ensureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed0, _ := backup.DerivePairwiseSeed(root, 0, 0)
	foreign := appSeeds(1)[0]
	code, out := call(t, s, s.handleInception, "/api/inception",
		map[string]any{"public_key": verkeyOf(seed0), "next_public_key": verkeyOf(foreign)})
	if code != http.StatusCreated {
		t.Fatalf("founding: %d %v", code, out)
	}
	evs, _ := s.DataStore.GetEvents(out["aid"].(string))
	if len(evs) != 1 || len(evs[0].ControllerSignatures()) != 0 {
		t.Fatalf("a founding committing to a foreign next key was signed here: %+v", evs)
	}
}

// A signature is attached after the fact only to an event an earlier version
// added unsigned, and only one that verifies over its stored bytes. An event
// stored unsigned since the upgrade is never signed in place.
func TestOnlyAnEventMarkedAtUpgradeIsSignedInPlace(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(2)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	icp := preparedBytes(t, out)
	good := appSign(t, k[0], icp, true)
	call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{good}})
	own, _ := s.DataStore.GetIdentity()
	sq := s.DataStore.(*store.SQLiteStore)
	strip := func(marked int) {
		if _, err := sq.DB().Exec(`UPDATE kel SET cesr_signature = '', signatures = '', unsigned_at_upgrade = ? WHERE aid = ?`,
			marked, own.AID); err != nil {
			t.Fatal(err)
		}
		s.KeriDriver = keriengine.New()
		s.engineSigns()
		s.reloadIdentityIntoDriver()
	}
	attach := func(sig string) int {
		code, _ := call(t, s, s.handleAttachEventSignature, "/api/events/signature",
			map[string]any{"aid": own.AID, "sequence_number": 0, "cesr_signature": sig})
		return code
	}

	strip(0)
	if code := attach(good); code != http.StatusConflict {
		t.Fatalf("an event stored unsigned since the upgrade was signed in place: %d", code)
	}
	strip(1)
	if code := attach(appSign(t, k[1], icp, true)); code != http.StatusBadRequest {
		t.Fatalf("a signature by the wrong key was attached: %d", code)
	}
	if code := attach(good); code != http.StatusOK {
		t.Fatalf("the right signature over a marked event: %d", code)
	}
	if code := attach(good); code != http.StatusOK {
		t.Fatalf("recording the same signature again: %d", code)
	}
	evs, _ := s.DataStore.GetEvents(own.AID)
	if len(evs[0].ControllerSignatures()) != 1 {
		t.Fatalf("the founding holds %d signatures", len(evs[0].ControllerSignatures()))
	}
}

// An app signing remotely as the owner, the signer these routes are for, is
// served: the gate spends its signature when it checks it, and the handler
// does not ask for it again.
func TestARemoteOwnerPreparesAnEvent(t *testing.T) {
	s := appHeldCore(t)
	seed, _ := sealTestOwner(t, s)
	r := s.buildRouter("")
	k := appSeeds(2)
	body, _ := json.Marshal(map[string]any{"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1",
		"n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, signed(t, http.MethodPost, "/api/events/prepare", string(body), seed, time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("a remote owner's signed prepare was answered %d %s", rec.Code, rec.Body.String())
	}
}
