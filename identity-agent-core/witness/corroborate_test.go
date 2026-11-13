package witness

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A verifier outside the core finds the witnesses a log designates through the
// registry, never through what a server says about itself. These stand up
// servers that answer like witnesses, because the question is who is asked.

const corroKey = "BDesignatedWitnessKeyForCorroborationTests0000"

func corroPresented(extra map[string]interface{}) []map[string]interface{} {
	ev := map[string]interface{}{"t": "icp", "i": "EOrg", "s": "0", "d": "EInception", "b": []interface{}{corroKey}}
	for k, v := range extra {
		ev[k] = v
	}
	raw, _ := json.Marshal(ev)
	return []map[string]interface{}{{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw)}}
}

// corroServer answers /witness/kel/ with the given body, and /health as the
// given identity, which is what ANY server can do.
func corroServer(t *testing.T, claimsAs string, kel string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"service_aid": claimsAs})
	})
	mux.HandleFunc("/witness/kel/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(kel)) })
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

const wholeLog = `{"kel":[{"t":"icp","i":"EOrg","s":"0","d":"EInception"}]}`

func TestAWitnessIsFoundThroughTheRegistryAndAWholeLogCorroborates(t *testing.T) {
	s := corroServer(t, corroKey, wholeLog)
	pool := []BootstrapWitness{{AID: corroKey, WitnessKey: corroKey, URL: s.URL}}
	got := Corroborate(nil, pool, "EOrg", corroPresented(nil))
	if !got.Corroborated() || got.Held != 1 || got.Asked != 1 || len(got.Answers) != 1 || got.Answers[0].URL != s.URL {
		t.Fatalf("a registered witness holding exactly the log did not corroborate it: %+v", got)
	}
}

// THE CASE THIS EXISTS FOR. A server that says it is the designated witness,
// and holds exactly the log, is not that witness unless the registry says so.
func TestAServerClaimingToBeTheWitnessIsNotAskedWhenTheRegistryDoesNotListIt(t *testing.T) {
	fake := corroServer(t, corroKey, wholeLog)
	// The registry knows another witness's key at the fake's address, and the
	// designated key at no address at all.
	pool := []BootstrapWitness{
		{AID: "BSomeoneElse", WitnessKey: "BSomeoneElse", URL: fake.URL},
		{AID: corroKey, WitnessKey: corroKey}, // no URL: nowhere to ask
	}
	got := Corroborate(nil, pool, "EOrg", corroPresented(nil))
	if got.Corroborated() || got.Asked != 0 || got.Held != 0 || got.Failed != 1 || len(got.Answers) != 0 {
		t.Fatalf("a server that only claims the designated identity was asked or counted: %+v", got)
	}
}

func TestAnEmptyRegistryAsksNobody(t *testing.T) {
	fake := corroServer(t, corroKey, wholeLog)
	_ = fake
	got := Corroborate(nil, nil, "EOrg", corroPresented(nil))
	if got.Corroborated() || got.Asked != 0 || got.Failed != 1 {
		t.Fatalf("with no registry somebody was asked: %+v", got)
	}
}

// Duplicity evidence is a contradiction even when the held log matches.
func TestAnEmptyConflictingListIsNotDuplicity(t *testing.T) {
	s := corroServer(t, corroKey, `{"kel":[{"t":"icp","i":"EOrg","s":"0","d":"EInception"}],"conflicting":[]}`)
	pool := []BootstrapWitness{{AID: corroKey, WitnessKey: corroKey, URL: s.URL}}
	if got := Corroborate(nil, pool, "EOrg", corroPresented(nil)); got.Contradicted || !got.Corroborated() {
		t.Fatalf("an empty conflicting list contradicted an honest log: %+v", got)
	}
}

func TestAWitnessHoldingALongerHistoryContradicts(t *testing.T) {
	s := corroServer(t, corroKey, `{"kel":[{"t":"icp","i":"EOrg","s":"0","d":"EInception"},{"t":"rot","i":"EOrg","s":"1","d":"ERot"}]}`)
	pool := []BootstrapWitness{{AID: corroKey, WitnessKey: corroKey, URL: s.URL}}
	if got := Corroborate(nil, pool, "EOrg", corroPresented(nil)); !got.Contradicted {
		t.Fatalf("a longer history at the witness did not contradict: %+v", got)
	}
}

func TestALogDesignatingNoWitnessAsksNobody(t *testing.T) {
	s := corroServer(t, corroKey, wholeLog)
	pool := []BootstrapWitness{{AID: corroKey, WitnessKey: corroKey, URL: s.URL}}
	got := Corroborate(nil, pool, "EOrg", corroPresented(map[string]interface{}{"b": []interface{}{}}))
	if got.Designated != 0 || got.Asked != 0 || got.Corroborated() {
		t.Fatalf("%+v", got)
	}
}

// A caller that knows the witnesses in force after a rotation names them.
func TestCorroborateThroughAsksTheKeysItIsGivenThroughTheRegistry(t *testing.T) {
	const rotatedTo = "BWitnessInForceAfterARotation00000000000000000"
	s := corroServer(t, rotatedTo, wholeLog)
	pool := []BootstrapWitness{{AID: rotatedTo, WitnessKey: rotatedTo, URL: s.URL}}
	got := CorroborateThrough(nil, pool, "EOrg", corroPresented(nil), []string{rotatedTo})
	if !got.Corroborated() || got.Asked != 1 {
		t.Fatalf("%+v", got)
	}
	// The inception's witness is not in this pool, so Corroborate cannot ask it.
	if got := Corroborate(nil, pool, "EOrg", corroPresented(nil)); got.Asked != 0 || got.Failed != 1 {
		t.Fatalf("%+v", got)
	}
}

// A real, signed log, so that what a witness hands back as "conflicting" can be
// told from junk by checking its signature, which is the only way it can be.
type signedLog struct {
	records             []map[string]interface{}
	prefix              string
	saids               []string
	witness             string
	key0, key1, key2    keri.Signer
	next0, next1, next2 string
}

func record(raw []byte, sig string) map[string]interface{} {
	return map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": sig}
}

// buildSignedLog is icp (key0), rot to key1 (sn 1), ixn signed by key1 (sn 2).
func buildSignedLog(t *testing.T) *signedLog {
	t.Helper()
	l := &signedLog{}
	var err error
	gen := func(transferable bool) keri.Signer {
		s, e := keri.GenerateSigner(transferable)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	l.key0, l.key1, l.key2 = gen(true), gen(true), gen(true)
	w := gen(false)
	l.witness = pub(t, w)
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub(t, l.key0)},
		NextDigests: []string{digest(t, l.key1)}, Witnesses: []string{l.witness}})
	if err != nil {
		t.Fatal(err)
	}
	ie := parsed(t, icp)
	l.prefix = ie.Identifier
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: l.prefix, PriorSAID: ie.SAID, SN: 1,
		Keys: []string{pub(t, l.key1)}, NextDigests: []string{digest(t, l.key2)}})
	if err != nil {
		t.Fatal(err)
	}
	re := parsed(t, rot)
	ixn := l.ixn(t, re.SAID, l.key1, "a")
	l.saids = []string{ie.SAID, re.SAID, parsed(t, mustRawOf(ixn)).SAID}
	l.records = []map[string]interface{}{
		record(icp, signAt(t, l.key0, icp, keri.SamePlace(0))),
		record(rot, signAt(t, l.key1, rot, keri.SamePlace(0))),
		ixn,
	}
	return l
}

func mustRawOf(rec map[string]interface{}) []byte {
	b, _ := base64.StdEncoding.DecodeString(rec["raw_bytes_b64"].(string))
	return b
}

// ixn is an interaction at sn 2 after prior, signed by by, carrying a seal
// that makes it a different event for a different tag.
func (l *signedLog) ixn(t *testing.T, prior string, by keri.Signer, tag string) map[string]interface{} {
	t.Helper()
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: l.prefix, PriorSAID: prior, SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{"d":"E` + tag + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	return record(raw, signAt(t, by, raw, keri.SamePlace(0)))
}

func (l *signedLog) serve(t *testing.T, conflicting []map[string]interface{}) []BootstrapWitness {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"kel": l.records, "conflicting": conflicting})
	s := corroServer(t, l.witness, string(body))
	return []BootstrapWitness{{AID: l.witness, WitnessKey: l.witness, URL: s.URL}}
}

func TestOnlyAValidlySignedRivalIsDuplicity(t *testing.T) {
	l := buildSignedLog(t)
	// The key the log had already rotated away from at sn 2.
	staleKey := l.ixn(t, l.saids[1], l.key0, "b")
	// Signed by the key in force: the identity signed two events at sn 2.
	valid := l.ixn(t, l.saids[1], l.key1, "c")
	// Another identifier's event at the same place, correctly signed by its own key.
	other := buildSignedLog(t)
	elsewhere := other.ixn(t, other.saids[1], other.key1, "d")

	cases := []struct {
		name        string
		conflicting []map[string]interface{}
		ignored     int
		fails       bool
	}{
		{"the held event itself", []map[string]interface{}{l.records[2]}, 1, false},
		{"garbage bytes", []map[string]interface{}{{"raw_bytes_b64": base64.StdEncoding.EncodeToString([]byte("not an event")), "cesr_signature": "x"}}, 1, false},
		{"an empty object", []map[string]interface{}{{}}, 1, false},
		{"a key already rotated away from", []map[string]interface{}{staleKey}, 1, false},
		{"another identifier's event", []map[string]interface{}{elsewhere}, 1, false},
		{"a validly signed rival", []map[string]interface{}{valid}, 0, true},
		{"junk beside a validly signed rival", []map[string]interface{}{{}, valid}, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pool := l.serve(t, c.conflicting)
			got := Corroborate(nil, pool, l.prefix, l.records)
			if got.Contradicted != c.fails {
				t.Fatalf("contradicted = %v, want %v: %+v", got.Contradicted, c.fails, got)
			}
			if !c.fails && !got.Corroborated() {
				t.Fatalf("an honest claim was refused over an invalid conflicting entry: %+v", got)
			}
			if len(got.Answers) != 1 || got.Answers[0].Ignored != c.ignored {
				t.Fatalf("ignored = %+v, want %d", got.Answers, c.ignored)
			}
		})
	}
}
