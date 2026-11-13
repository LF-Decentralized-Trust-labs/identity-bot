package witness

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
func TestAWitnessHoldingDuplicityEvidenceContradicts(t *testing.T) {
	s := corroServer(t, corroKey, `{"kel":[{"t":"icp","i":"EOrg","s":"0","d":"EInception"}],`+
		`"conflicting":[{"t":"rot","i":"EOrg","s":"0","d":"ERival"}]}`)
	pool := []BootstrapWitness{{AID: corroKey, WitnessKey: corroKey, URL: s.URL}}
	got := Corroborate(nil, pool, "EOrg", corroPresented(nil))
	if !got.Contradicted || got.Corroborated() || got.Why == "" {
		t.Fatalf("a witness holding conflicting events did not contradict: %+v", got)
	}
	if len(got.Answers) != 1 || len(got.Answers[0].Conflicting) != 1 {
		t.Fatalf("the evidence was not handed back: %+v", got.Answers)
	}
}

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
