package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/witness"
)

// Asking somebody other than the claimant whether a history is complete.
//
// These stand up a real witness rather than a stub that returns yes, because
// the whole question is what a SECOND party holds — a stand-in that agrees with
// whatever it is shown would pass every test here while testing nothing.

// standInWitness serves the three things a witness has to answer for this to
// work: who it is, so it can be designated at all; the events it is sent; and
// its copy of an identity's log, which is the check.
type standInWitness struct {
	*httptest.Server
	mu  sync.Mutex
	key string
	// held is what this witness will say it holds, per identity. Set by a test
	// to stand for a history the claimant did not show.
	held map[string][]map[string]interface{}
}

func newStandInWitness(t *testing.T) *standInWitness {
	t.Helper()
	w := &standInWitness{ // A well-formed non-transferable identifier. It has to be: the engine
		// refuses to designate anything else, because a receipt from a
		// transferable identifier could not be checked without first resolving
		// that witness's own key log.
		key: iacrypto.NonTransferableAIDQB64(aWitnessKey(7)), held: map[string][]map[string]interface{}{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"service_aid": w.key})
	})
	mux.HandleFunc("/witness/event", func(rw http.ResponseWriter, r *http.Request) {
		// Record what it is sent, as a real witness does. A stand-in that
		// accepted events and remembered nothing would report every identity as
		// unknown, and the honest path would look identical to an attack.
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		ev, _ := body["event"].(map[string]interface{})
		if ev == nil {
			if raw, ok := body["raw_event"].(string); ok {
				var parsed map[string]interface{}
				if json.Unmarshal([]byte(raw), &parsed) == nil {
					ev = parsed
				}
			}
		}
		if aid, _ := ev["i"].(string); aid != "" {
			w.mu.Lock()
			w.held[aid] = append(w.held[aid], ev)
			w.mu.Unlock()
		}
		json.NewEncoder(rw).Encode(map[string]any{"ok": true})
	})
	// What it holds, said the way a witness says it now: a key state notice
	// signed by the witness's own key. The copy of the log below is what it
	// serves besides, and is not what it is believed by.
	mux.HandleFunc("/witness/ksn/", func(rw http.ResponseWriter, r *http.Request) {
		aid := r.URL.Path[len("/witness/ksn/"):]
		w.mu.Lock()
		kel := w.held[aid]
		w.mu.Unlock()
		sn, said := len(kel)-1, ""
		if sn >= 0 {
			said = standInDigest(kel[sn])
		}
		raw, err := buildNoticeOf(w.key, aid, sn, said, time.Now())
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		sig, _ := login.SignString(string(raw), bytes.Repeat([]byte{7}, 32))
		json.NewEncoder(rw).Encode(witness.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), WitnessAID: w.key, Signature: sig})
	})
	mux.HandleFunc("/witness/kel/", func(rw http.ResponseWriter, r *http.Request) {
		aid := r.URL.Path[len("/witness/kel/"):]
		// One event of the log, as a witness hands it over by place.
		place := -1
		if i := strings.Index(aid, "/event/"); i >= 0 {
			place, _ = strconv.Atoi(aid[i+len("/event/"):])
			aid = aid[:i]
		}
		w.mu.Lock()
		kel, ok := w.held[aid]
		w.mu.Unlock()
		if !ok || (place >= len(kel)) {
			http.NotFound(rw, r)
			return
		}
		if place >= 0 {
			json.NewEncoder(rw).Encode(kel[place])
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"aid": aid, "kel": kel, "count": len(kel)})
	})
	w.Server = httptest.NewServer(mux)
	t.Cleanup(w.Close)

	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness {
		return []witness.BootstrapWitness{{
			AID: "EStandInWitness", WitnessKey: w.key, URL: w.URL, Operator: "tests",
		}}
	}
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })
	return w
}

// THE CASE THIS EXISTS FOR. A claimant shows a log with the last event removed
// and signs with the key that log puts in force. Everything about the claim
// verifies; the identity has already moved on.
func TestAHistoryWithARotationWithheldIsRefused(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)
	c := newRotatingControllerWitnessedBy(t, "claimant", w.key)

	presented := []map[string]interface{}{inceptionRecordOf(c)}
	// The witness saw a rotation the claim did not show, and hands it over.
	w.held[c.aid] = []map[string]interface{}{inceptionRecordOf(c), signedRotation(t, c)}

	got := s.askTheWitnesses(c.aid, presented)
	if !got.Contradicted {
		t.Fatalf("a witness holding a longer history than the claim showed did not "+
			"contradict it: %+v", got)
	}
	if got.Why == "" {
		t.Error("contradicted, but with no reason a refusal could quote")
	}
}

// The same history, whole. It must not be refused.
//
// Without this a check that contradicted everything would pass the test above
// and make every honest claim fail.
func TestAWholeHistoryIsHeldButAnUnreceiptedOneIsNotCorroborated(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)
	c := newRotatingControllerWitnessedBy(t, "claimant", w.key)

	kel := []map[string]interface{}{inceptionRecordOf(c)}
	w.held[c.aid] = []map[string]interface{}{inceptionRecordOf(c)}

	got := s.askTheWitnesses(c.aid, kel)
	if got.Contradicted {
		t.Fatalf("an honest, complete history was contradicted: %s", got.Why)
	}
	// The witness states, signed and now, that this is the newest event it
	// holds. That is the live half. The log states no threshold and carries no
	// receipts, so the other half is missing and it is not corroborated: that a
	// witness says it holds an event is not that the event was witnessed. The
	// whole of it, receipted and held, is TestAVerifierCorroboratesAWholeHistoryThroughARealWitness.
	if got.Held != 1 || got.ReceiptsMet || got.Corroborated() {
		t.Fatalf("a log with no receipts was corroborated, or its witness not counted: %+v", got)
	}
}

// inceptionRecordOf is the controller's inception as a verifier is shown it: the
// published bytes and the controller's signature.
func inceptionRecordOf(c *rotatingController) map[string]interface{} {
	return map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(c.icpRaw), "cesr_signature": c.icpSig}
}

// signedRotation is the controller's real rotation to its next key, signed by it.
func signedRotation(t *testing.T, c *rotatingController) map[string]interface{} {
	t.Helper()
	p1, _ := c.signers[1].PublicKey()
	p2, _ := c.signers[2].PublicKey()
	rot, err := c.eng.Rotate(drivers.RotationRequest{Name: c.name, NewPublicKey: p1, NewNextPublicKey: p2})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(rot.RawBytesB64)
	return map[string]interface{}{"raw_bytes_b64": rot.RawBytesB64, "cesr_signature": sign(t, c.signers[1], raw)}
}

// signedInteractionAt is an interaction at sn after prior, signed by by, that
// carries tag so that two of them differ.
func signedInteractionAt(t *testing.T, c *rotatingController, sn int, prior, tag string, by keri.Signer) map[string]interface{} {
	t.Helper()
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: c.aid, PriorSAID: prior, SN: sn,
		Data: []json.RawMessage{json.RawMessage(`{"d":"E` + tag + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": sign(t, by, raw)}
}

// A witness that cannot be reached leaves the history uncorroborated. It does
// NOT mean the claim is refuted — conflating the two makes every network fault
// look like an attack.
func TestAnUnreachableWitnessIsNotAContradiction(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)
	kel := []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{w.key}},
	}
	w.Close() // down, as far as anyone claiming is concerned

	got := s.askTheWitnesses("EClaimant", kel)
	if got.Contradicted {
		t.Fatal("an unreachable witness was treated as refuting the claim")
	}
	if got.Corroborated() {
		t.Fatal("a history nobody could confirm was reported as corroborated")
	}
	if got.Designated != 1 {
		t.Errorf("the log names one witness; got %d", got.Designated)
	}
}

// An identity that named no witnesses can never be corroborated, and says so
// rather than appearing to pass.
func TestAnIdentityThatNamedNoWitnessesIsNotCorroborated(t *testing.T) {
	s := agentWithNoIdentity(t)
	got := s.askTheWitnesses("EClaimant", []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0"},
	})
	if got.Corroborated() || got.Designated != 0 {
		t.Fatalf("an identity with no designated witnesses was reported as %+v", got)
	}
}

// The policy: where a machine cannot ask, what it does depends on whether being
// unable to ask is meaningful.
func TestOnlyAMachineThatCanAlwaysReachAWitnessRefusesForNotReaching(t *testing.T) {
	s := agentWithNoIdentity(t)

	resetLocalPairingOfferForTest()
	if !s.mustBeCorroborated() {
		t.Fatal("a machine somebody else set up does not require corroboration — it was " +
			"reached by a provisioning host, so being unable to reach a witness is a signal")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/offer-this-computer", nil)
	req.RemoteAddr = "127.0.0.1:5050"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	s.handleOfferThisComputer(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("could not offer the computer: %s", rec.Body.String())
	}
	if s.mustBeCorroborated() {
		t.Fatal("a computer offered from its own screen requires corroboration, so one being " +
			"set up with no working network could never be paired — which is the ordinary case")
	}
	t.Cleanup(resetLocalPairingOfferForTest)
}

// A log arrives in two shapes, and reading only one silently disables the check.
//
// A witness serves parsed events, with the fields at the top level. This
// agent's own store keeps records, with the event as text under event_json.
// The first version of this read only the parsed shape, so every claim carrying
// a stored log came back "0 witnesses named" — not an error, not a refusal,
// just a check that quietly established nothing. That is worse than a bug that
// fails, so both shapes are asserted.
func TestWitnessKeysAreFoundInEitherShapeOfLog(t *testing.T) {
	const key = "BAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH"

	parsed := []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{key}},
	}
	stored := []map[string]interface{}{
		{
			"event_type":      "icp",
			"sequence_number": 0,
			"event_json":      `{"t":"icp","i":"EClaimant","s":"0","b":["` + key + `"]}`,
		},
	}

	for name, kel := range map[string][]map[string]interface{}{
		"as a witness serves it": parsed,
		"as the store keeps it":  stored,
	} {
		got := witnessKeysIn(kel)
		if len(got) != 1 || got[0] != key {
			t.Errorf("%s: the designated witness was not found (%v), so nothing would be "+
				"asked and the history would pass unchecked", name, got)
		}
	}
}

// What a machine founds is witnessed too.
//
// Witnesses can only be named in the inception event, so an identity founded
// without them can never be corroborated by anybody for as long as it exists.
// Nothing a machine founded ever had any — not a paired computer and not an
// organisation — which is sharpest for an organisation, whose own key log is
// what counterparties check for the rest of its life.
func TestAnIdentityAMachineFoundsNamesItsWitnesses(t *testing.T) {
	// About what a machine founds, not about where founding is allowed.
	// These run on the machines the platform check refuses, so this
	// stands in for one that may found.
	aMachineThatMayFound(t)
	wit := newStandInWitness(t)
	machine, srv, code := pairableComputer(t)
	owner := adoptingOwner(t)

	// The owner's identity has to be corroborable for the claim to be accepted
	// at all; this test is about the OTHER side — what the machine founds.
	wit.mu.Lock()
	_ = wit.held
	wit.mu.Unlock()

	if rec := claimAs(t, owner, srv.URL, code, ""); rec.Code != http.StatusOK {
		t.Fatalf("claim failed: %s", rec.Body.String())
	}

	founded, err := machine.DataStore.GetIdentity()
	if err != nil || founded == nil {
		t.Fatal("the machine founded no identity")
	}
	events, err := machine.DataStore.GetEvents(founded.AID)
	if err != nil || len(events) == 0 {
		t.Fatalf("no key log for what it founded: %v", err)
	}

	var ev map[string]interface{}
	if err := json.Unmarshal([]byte(events[0].EventJSON), &ev); err != nil {
		t.Fatalf("its inception does not parse: %v", err)
	}
	b, _ := ev["b"].([]interface{})
	if len(b) == 0 {
		t.Fatal("the identity this machine founded names no witnesses, so nothing can " +
			"ever corroborate its history — and a witness cannot be added afterwards, " +
			"because they are named in the inception event or not at all")
	}
	if got, _ := b[0].(string); got != wit.key {
		t.Errorf("named %q, expected the witness it could actually reach (%q)", got, wit.key)
	}

	// And it must be signed, or the witnesses it named could never attest to it.
	if events[0].CesrSignature == "" || events[0].RawBytesB64 == "" {
		t.Error("its inception was stored without the signature and canonical bytes a " +
			"witness checks, so naming witnesses buys nothing")
	}
}

// A machine that can reach no witness still founds. It says so rather than
// refusing: a computer being set up may have no route out at all, which is the
// ordinary case rather than an exotic one.
func TestAMachineWithNoWitnessAvailableStillFounds(t *testing.T) {
	// About what a machine founds, not about where founding is allowed.
	// These run on the machines the platform check refuses, so this
	// stands in for one that may found.
	aMachineThatMayFound(t)
	machine, srv, code := pairableComputer(t)
	owner := adoptingOwner(t)

	if rec := claimAs(t, owner, srv.URL, code, ""); rec.Code != http.StatusOK {
		t.Fatalf("a machine that could reach no witness refused to be claimed: %s", rec.Body.String())
	}
	if id, _ := machine.DataStore.GetIdentity(); id == nil {
		t.Fatal("it founded nothing")
	}
}

// standInDigest is the digest of an event a stand-in holds: its own d, or the d
// in the bytes it was held as. "" when it has none, which a witness cannot say.
func standInDigest(ev map[string]interface{}) string {
	if d, _ := ev["d"].(string); d != "" {
		return d
	}
	if b, _ := ev["raw_bytes_b64"].(string); b != "" {
		raw, _ := base64.StdEncoding.DecodeString(b)
		var in struct {
			D string `json:"d"`
		}
		_ = json.Unmarshal(raw, &in)
		return in.D
	}
	return ""
}

// receipts has the stand-in receipt every event it holds for aid that it holds
// as bytes, as a witness that took them from their controller would: indexed
// signatures over the event's bytes, at its place (0) in a list of one.
func (w *standInWitness) receipts(t *testing.T, aid string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, rec := range w.held[aid] {
		b, _ := rec["raw_bytes_b64"].(string)
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil || len(raw) == 0 {
			t.Fatalf("an event the stand-in cannot receipt, held without its bytes: %v", rec)
		}
		sig, err := drivers.SignEventReceipt(raw, bytes.Repeat([]byte{7}, 32), 0)
		if err != nil {
			t.Fatal(err)
		}
		rec["witness_receipts"] = []interface{}{map[string]interface{}{"witness": w.key, "cesr_signature": sig}}
	}
}

// buildNoticeOf is a notice by witnessKey that states the log of aid as at place
// sn with digest said, for stand-in witnesses that hold no whole log.
func buildNoticeOf(witnessKey, aid string, sn int, said string, at time.Time) ([]byte, error) {
	rec := witness.NoKeyState(aid)
	if sn >= 0 {
		rec.S, rec.D = strconv.FormatInt(int64(sn), 16), said
	}
	return witness.BuildKeyStateNotice(witnessKey, rec, at)
}
