package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/keymath"
	"identity-agent-core/recovery"

	keri "github.com/grapeid/keri-go"
)

// The logs this core produces, handed to keripy 1.3.6 to accept or refuse.
//
// keri-go already checks its own library calls against keripy (its interop/
// directory). What that cannot show is the events this core produces when an
// app prepares, signs and commits them: the fields the core chooses, the order
// it writes them, the signatures it keeps. This test drives the same handlers
// the other tests in this package drive, with the app's Ed25519 signatures,
// and writes each signed log out as one CESR stream for
// identity-agent-core/interop/verify_keripy.py to judge.
//
//	IDENTITY_BOT_INTEROP_OUT=/tmp/cases.json go test ./server -run TestKeripyJudges
//	python3 -I interop/verify_keripy.py /tmp/cases.json     (in a venv with keri==1.3.6)
//
// Without the variable it still drives every shape and checks keri-go accepts
// the log; it only writes nothing.

type keripyCase struct {
	Label  string   `json:"label"`
	Why    string   `json:"why"`
	Event  string   `json:"event_b64"`   // the last event, which keripy must end up at
	Stream string   `json:"message_b64"` // the whole log, signatures attached, in one stream
	Extra  []string `json:"extra_b64,omitempty"`
}

var keripyCases []keripyCase

func b64s(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func joined(messages [][]byte) []byte {
	var out []byte
	for _, m := range messages {
		out = append(out, m...)
	}
	return out
}

// record keeps the core's log as a case, after checking keri-go accepts it too.
func record(t *testing.T, label, why string, messages [][]byte, last []byte, extra ...[]byte) {
	t.Helper()
	if _, err := keri.ValidateSignedKEL(messages); err != nil {
		t.Fatalf("%s: the log does not verify even by keri-go: %v", label, err)
	}
	c := keripyCase{Label: label, Why: why, Event: b64s(last), Stream: b64s(joined(messages))}
	for _, e := range extra {
		c.Extra = append(c.Extra, b64s(e))
	}
	keripyCases = append(keripyCases, c)
}

// prepareAndCommit is one event through the two routes, signed by seed as the
// app would. opens says the signature opens the prior commitment (rot, icp).
func prepareAndCommit(t *testing.T, s *CoreServer, req map[string]any, seed []byte, opens bool) (raw []byte, res map[string]any) {
	t.Helper()
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", req)
	if code != http.StatusOK {
		t.Fatalf("prepare %v: %d %v", req["t"], code, out)
	}
	raw = preparedBytes(t, out)
	code, res = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": b64s(raw), "sigs": []string{appSign(t, seed, raw, opens)}})
	if code != http.StatusCreated {
		t.Fatalf("commit %v: %d %v", req["t"], code, res)
	}
	return raw, res
}

// commits is what every establishment event the app makes commits to: the
// digest of its next signing key, and the digest of a post-quantum key it keeps
// in reserve, with a threshold of one (the app's shape; ADR-061).
func commits(t *testing.T, next, reserve []byte) []string {
	t.Helper()
	pq, err := keymath.PostQuantumNextKey(reserve)
	if err != nil {
		t.Fatal(err)
	}
	return []string{digestOfSeed(t, next), pq.Digest}
}

// messagingAnchor stands in for the messaging keyset the app anchors at founding.
var messagingAnchor = []any{map[string]string{"d": "EMessagingKeysetAnchoredAtFounding"}}

func founding(t *testing.T, s *CoreServer, key, next []byte, extra map[string]any) (aid string, tip map[string]string) {
	t.Helper()
	req := map[string]any{"t": "icp", "k": []string{verkeyOf(key)}, "kt": "1", "n": commits(t, next, reserveFor(next)), "nt": "1",
		"a": messagingAnchor}
	for k, v := range extra {
		req[k] = v
	}
	_, res := prepareAndCommit(t, s, req, key, true)
	return res["d"].(string), map[string]string{"s": "0", "d": res["d"].(string)}
}

// reserveFor is the post-quantum reserve committed beside next: another seed,
// derived from it so each establishment event commits to a different one.
func reserveFor(next []byte) []byte {
	r := append([]byte{}, next...)
	r[31] ^= 0x5A
	return r
}

func tipOf(res map[string]any) map[string]string {
	return map[string]string{"s": res["s"].(string), "d": res["d"].(string)}
}

func TestKeripyJudges(t *testing.T) {
	keripyCases = nil
	k := appSeeds(10) // [0..4] the first phrase, [5..9] a new phrase

	t.Run("founding", func(t *testing.T) {
		s := appHeldCore(t)
		aid, _ := founding(t, s, k[0], k[1], nil)
		m, last := storedLog(t, s, aid)
		record(t, "core/founding", "a founding the core prepared, signed by the app", m, last)
	})

	t.Run("rotation", func(t *testing.T) {
		s := appHeldCore(t)
		aid, after := founding(t, s, k[0], k[1], nil)
		prepareAndCommit(t, s, map[string]any{"aid": aid, "t": "rot", "k": []string{verkeyOf(k[1])}, "kt": "1",
			"n": commits(t, k[2], reserveFor(k[2])), "nt": "1", "after": after}, k[1], true)
		m, last := storedLog(t, s, aid)
		record(t, "core/rotation", "a rotation revealing the committed key", m, last)
	})

	t.Run("interaction", func(t *testing.T) {
		s := appHeldCore(t)
		aid, after := founding(t, s, k[0], k[1], nil)
		_, res := prepareAndCommit(t, s, map[string]any{"aid": aid, "t": "ixn",
			"a": []any{map[string]string{"d": "EAnchoredByTheOwner"}}, "after": after}, k[0], false)
		prepareAndCommit(t, s, map[string]any{"aid": aid, "t": "ixn",
			"a": []any{map[string]string{"d": "EAnchoredAgain"}}, "after": tipOf(res)}, k[0], false)
		m, last := storedLog(t, s, aid)
		record(t, "core/interaction", "two interactions after a founding", m, last)
	})

	t.Run("recovery", func(t *testing.T) {
		s := appHeldCore(t)
		aid, after := founding(t, s, k[0], k[1], nil)
		var kept map[string]string
		for i, d := range []string{"EKeptByTheOwner", "EAnchoredByAThief", "EAlsoByTheThief"} {
			_, res := prepareAndCommit(t, s, map[string]any{"aid": aid, "t": "ixn",
				"a": []any{map[string]string{"d": d}}, "after": after}, k[0], false)
			after = tipOf(res)
			if i == 0 {
				kept = after
			}
		}
		// What keripy saw before the recovery: the thief's interactions are in its log.
		before, _ := storedLog(t, s, aid)
		if len(before) != 4 {
			t.Fatalf("the log before the recovery holds %d events; the case needs the founding and three interactions", len(before))
		}

		code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": aid,
			"t": "rot", "k": []string{verkeyOf(k[1])}, "kt": "1", "n": commits(t, k[2], reserveFor(k[2])), "nt": "1", "after": kept})
		if code != http.StatusOK {
			t.Fatalf("prepare recovery rotation: %d %v", code, out)
		}
		rot := preparedBytes(t, out)
		rec := httptest.NewRecorder()
		if _, ok := s.commitRecoveryRotation(rec, recovery.RotationRequest{RawB64: b64s(rot),
			Sigs: []string{appSign(t, k[1], rot, true)}}); !ok {
			t.Fatalf("the recovery rotation was refused: %d %s", rec.Code, rec.Body.String())
		}
		after2, last := storedLog(t, s, aid)
		// Only the stored log is in keri-go's validator's reach; the replay with the
		// superseded interactions is what keripy alone judges.
		record(t, "core/recovery-stored-log", "the log the core keeps after a recovery rotation set the thief's interactions aside", after2, last)
		replay := append(append([][]byte{}, before...), after2[len(after2)-1])
		keripyCases = append(keripyCases, keripyCase{Label: "core/recovery-superseding",
			Why:   "a recovery rotation arriving after the interactions it supersedes, as a verifier that saw them would receive it",
			Event: b64s(last), Stream: b64s(joined(replay))})
	})

	t.Run("move to a new phrase", func(t *testing.T) {
		s := appHeldCore(t)
		aid, after := founding(t, s, k[0], k[1], nil)
		// Step 1 reveals the old phrase's key and commits to the new phrase's keys.
		_, res := prepareAndCommit(t, s, map[string]any{"aid": aid, "t": "rot", "k": []string{verkeyOf(k[1])}, "kt": "1",
			"n": commits(t, k[6], reserveFor(k[6])), "nt": "1", "after": after}, k[1], true)
		// Step 2 reveals the new phrase's key 1 and commits to its key 2.
		prepareAndCommit(t, s, map[string]any{"aid": aid, "t": "rot", "k": []string{verkeyOf(k[6])}, "kt": "1",
			"n": commits(t, k[7], reserveFor(k[7])), "nt": "1", "after": tipOf(res)}, k[6], true)
		m, last := storedLog(t, s, aid)
		record(t, "core/move-to-a-new-phrase", "two rotations: the old phrase's key, then the new phrase's key 1", m, last)
	})

	t.Run("witnessed founding", func(t *testing.T) {
		s := appHeldCore(t)
		var wits []string
		var wkeys []ed25519.PrivateKey
		for i := 0; i < 2; i++ {
			seed := make([]byte, 32)
			seed[0], seed[1] = 0xC3, byte(i+1)
			priv := ed25519.NewKeyFromSeed(seed)
			wkeys = append(wkeys, priv)
			wits = append(wits, iacrypto.NonTransferableAIDQB64(priv.Public().(ed25519.PublicKey)))
		}
		aid, _ := founding(t, s, k[0], k[1], map[string]any{"b": wits, "bt": "2"})
		m, last := storedLog(t, s, aid)
		ev, err := keri.ParseEvent(last)
		if err != nil || len(ev.Witnesses) != 2 || !ev.HasTOAD || ev.TOAD != 2 {
			t.Fatalf("the founding does not carry its witnesses: %+v %v", ev, err)
		}
		// The witnesses are played here: each signs the event and receipts it.
		var receipts [][]byte
		for i, w := range wkeys {
			cigar, err := keri.MatterQB64(keri.CodeEd25519Sig, ed25519.Sign(w, last))
			if err != nil {
				t.Fatal(err)
			}
			stream, err := keri.BuildReceiptStream(keri.ReceiptInput{Prefix: ev.Identifier, SN: 0, EventSAID: ev.SAID},
				[]keri.ReceiptCouple{{Witness: wits[i], CigarQB64: cigar}})
			if err != nil {
				t.Fatal(err)
			}
			receipts = append(receipts, stream)
		}
		record(t, "core/witnessed-founding", "a founding naming two witnesses with a threshold of two, receipted by both", m, last, receipts...)
	})

	if out := os.Getenv("IDENTITY_BOT_INTEROP_OUT"); out != "" {
		b, _ := json.MarshalIndent(keripyCases, "", " ")
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
