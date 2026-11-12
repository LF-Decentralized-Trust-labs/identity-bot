package witnessproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

func seeded(b byte) *keri.SoftwareSigner {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	s, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		panic(err)
	}
	return s
}

func sigsAt(t *testing.T, raw []byte, signers map[int]*keri.SoftwareSigner) []string {
	t.Helper()
	var placed []keri.PlacedSigner
	for at := 0; at < 8; at++ {
		if s, ok := signers[at]; ok {
			placed = append(placed, keri.PlacedSigner{Signer: s, At: keri.SamePlace(at)})
		}
	}
	se, err := keri.SignEventAt(raw, placed...)
	if err != nil {
		t.Fatal(err)
	}
	att := string(se.Attachment)[4:] // after the counter
	var out []string
	for len(att) > 0 {
		out = append(out, att[:88])
		att = att[88:]
	}
	return out
}

// TestRegenerate writes the fixture. It is deterministic: the keys are fixed
// test keys, never to be trusted anywhere.
func TestRegenerate(t *testing.T) {
	if os.Getenv("REGENERATE_KEL_FIXTURE") == "" {
		t.Skip("set REGENERATE_KEL_FIXTURE=1 to write kel-log-contract-fixture.json")
	}
	cur := []*keri.SoftwareSigner{seeded(0x10), seeded(0x30), seeded(0x50)}
	next := []*keri.SoftwareSigner{seeded(0x70), seeded(0x90), seeded(0xb0)}
	later := []*keri.SoftwareSigner{seeded(0xd0), seeded(0xe0), seeded(0xf0)}
	pubs := func(ss []*keri.SoftwareSigner) (out []string) {
		for _, s := range ss {
			p, _ := s.PublicKey()
			out = append(out, p)
		}
		return
	}
	digs := func(ss []*keri.SoftwareSigner) (out []string) {
		for _, p := range pubs(ss) {
			d, err := keri.NextDigest(p)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return
	}
	two := json.RawMessage(`"2"`)
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: pubs(cur), NextDigests: digs(next), Isith: two, Nsith: two, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	e0, _ := keri.ParseEvent(icp)
	aid := e0.Identifier
	ixn := func(sn int, prior string, label string) []byte {
		raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: prior, SN: sn,
			Data: []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"d":%q}`, label))}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	ix1 := ixn(1, e0.SAID, "one")
	e1, _ := keri.ParseEvent(ix1)
	ix2 := ixn(2, e1.SAID, "honest")
	e2, _ := keri.ParseEvent(ix2)
	rival := ixn(2, e1.SAID, "rival")
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: aid, PriorSAID: e2.SAID, SN: 3, Keys: pubs(next),
		NextDigests: digs(later), Isith: two, Nsith: two})
	if err != nil {
		t.Fatal(err)
	}
	// Two of three sign each event: different pairs, so no one key is the one.
	events := []struct {
		raw  []byte
		sigs []string
	}{
		{icp, sigsAt(t, icp, map[int]*keri.SoftwareSigner{0: cur[0], 1: cur[1]})},
		{ix1, sigsAt(t, ix1, map[int]*keri.SoftwareSigner{0: cur[0], 2: cur[2]})},
		{ix2, sigsAt(t, ix2, map[int]*keri.SoftwareSigner{1: cur[1], 2: cur[2]})},
		{rot, sigsAt(t, rot, map[int]*keri.SoftwareSigner{0: next[0], 1: next[1]})},
	}
	rivalSigs := sigsAt(t, rival, map[int]*keri.SoftwareSigner{0: cur[0], 1: cur[1]})

	type sub struct {
		AID            string   `json:"aid"`
		EventB64       string   `json:"event_b64"`
		CesrSignature  string   `json:"cesr_signature"`
		CesrSignatures []string `json:"cesr_signatures"`
	}
	b64 := base64.StdEncoding.EncodeToString
	var subs []sub
	var kel []map[string]interface{}
	var parsed []map[string]interface{}
	for _, e := range events {
		subs = append(subs, sub{aid, b64(e.raw), e.sigs[0], e.sigs})
		var fields map[string]interface{}
		_ = json.Unmarshal(e.raw, &fields)
		parsed = append(parsed, fields)
		kel = append(kel, map[string]interface{}{"raw_bytes_b64": b64(e.raw), "cesr_signature": e.sigs[0], "cesr_signatures": e.sigs})
	}
	subs = append(subs, sub{aid, b64(rival), rivalSigs[0], rivalSigs})
	var rf map[string]interface{}
	_ = json.Unmarshal(rival, &rf)
	rivalSAID, _ := rf["d"].(string)
	conflicting := []map[string]interface{}{{
		"sequence_number": 2, "said": rivalSAID, "raw_bytes_b64": b64(rival), "cesr_signature": rivalSigs[0], "cesr_signatures": rivalSigs,
	}}
	var digests []map[string]interface{}
	for seq := range events {
		d, err := KelDigestAtSeq(parsed, seq)
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, map[string]interface{}{"seq": seq, "digest": d, "rival_at_or_below": seq >= 2})
	}
	out := map[string]interface{}{
		"description": "one key log as a watcher is sent it and as it serves it; see witnessproto.KelLogContractFixture",
		"aid":         aid, "rival_seq": 2, "submissions": subs,
		"served":  map[string]interface{}{"aid": aid, "kel": kel, "conflicting": conflicting, "count": len(kel)},
		"digests": digests,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile("kel-log-contract-fixture.json", append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The fixture is what it says: every submitted event verifies as a log (the
// rival in place of the event it conflicts with), under the keys' threshold,
// the served log is exactly the submissions without the rival, and the digests
// are the protocol's.
func TestTheContractFixtureIsAValidMultiKeyLogWithARival(t *testing.T) {
	c, err := ReadKelLogContract()
	if err != nil {
		t.Fatal(err)
	}
	msg := func(b64s string, sigs []string) []byte {
		raw, err := base64.StdEncoding.DecodeString(b64s)
		if err != nil {
			t.Fatal(err)
		}
		g, err := keri.AttachControllerSigs(sigs)
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, g...)
	}
	var held, branch [][]byte
	for i, s := range c.Submissions {
		m := msg(s.EventB64, s.CesrSignatures)
		if len(s.CesrSignatures) < 2 || s.CesrSignature != s.CesrSignatures[0] {
			t.Fatalf("submission %d is not multi-signed with its first signature as cesr_signature", i)
		}
		if i < len(c.Submissions)-1 {
			held = append(held, m)
		} else {
			branch = append(append([][]byte(nil), held[:c.RivalSeq]...), m)
		}
	}
	if _, err := keri.ValidateSignedKEL(held); err != nil {
		t.Fatalf("the held log does not verify: %v", err)
	}
	if _, err := keri.ValidateSignedKEL(branch); err != nil {
		t.Fatalf("the rival branch does not verify: %v", err)
	}
	if len(c.Served.KEL) != len(held) || c.Served.Count != len(held) || len(c.Served.Conflicting) != 1 {
		t.Fatalf("the served answer is not the held log and one rival")
	}
	for i, rec := range c.Served.KEL {
		sigs := toStrings(rec["cesr_signatures"])
		if rec["raw_bytes_b64"] != c.Submissions[i].EventB64 || strings.Join(sigs, ",") != strings.Join(c.Submissions[i].CesrSignatures, ",") {
			t.Fatalf("served event %d is not what was submitted", i)
		}
	}
	var events []map[string]interface{}
	for _, s := range c.Submissions[:len(held)] {
		raw, _ := base64.StdEncoding.DecodeString(s.EventB64)
		var ev map[string]interface{}
		_ = json.Unmarshal(raw, &ev)
		events = append(events, ev)
	}
	for _, d := range c.Digests {
		got, err := KelDigestAtSeq(events, d.Seq)
		if err != nil || got != d.Digest || d.RivalAtOrBelow != (d.Seq >= c.RivalSeq) {
			t.Fatalf("digest at %d: %q %v, fixture %q rival %v", d.Seq, got, err, d.Digest, d.RivalAtOrBelow)
		}
	}
}

func toStrings(v interface{}) (out []string) {
	if l, ok := v.([]interface{}); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return
}
