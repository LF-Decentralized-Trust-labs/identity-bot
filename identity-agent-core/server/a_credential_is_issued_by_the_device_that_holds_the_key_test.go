package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

func foundedAppHeld(t *testing.T) (*CoreServer, string, [][]byte) {
	t.Helper()
	s := appHeldCore(t)
	k := appSeeds(3)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	icp := preparedBytes(t, out)
	if code, out := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}}); code != http.StatusCreated {
		t.Fatalf("founding: %d %v", code, out)
	}
	own, _ := s.DataStore.GetIdentity()
	return s, own.AID, k
}

// An identity whose key the app holds issues a credential: the core builds it
// and says nothing is anchored, the app has the interaction that seals it
// prepared and committed, and only then does the core keep the credential. The
// core still refuses to issue it by itself, as it cannot sign the anchor.
func TestACredentialOfAnAppHeldIdentityIsKeptOnceTheAppAnchorsIt(t *testing.T) {
	s, aid, k := foundedAppHeld(t)

	if code, out := call(t, s, s.handleIssueCredential, "/api/credential/issue", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"}); code != http.StatusConflict || out["error"] != "key_not_held_here" {
		t.Fatalf("the core issued by itself an identity whose key it does not hold: %d %v", code, out)
	}

	code, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	if code != http.StatusOK {
		t.Fatalf("prepare credential: %d %v", code, out)
	}
	acdcB64 := out["acdc_json_b64"].(string)
	acdc, _ := base64.StdEncoding.DecodeString(acdcB64)
	cred, err := keri.VerifyCredential(acdc)
	if err != nil || cred.Issuer != aid || cred.Recipient != "Eholder" || cred.SAID != out["acdc_said"] {
		t.Fatalf("the credential is not the one asked for: %+v %v", cred, err)
	}
	if evs, _ := s.DataStore.GetEvents(aid); len(evs) != 1 {
		t.Fatalf("preparing a credential added %d events", len(evs)-1)
	}

	// Not anchored yet: nothing is kept, whatever digest is claimed.
	if code, _ := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": acdcB64, "ixn_said": aid}); code != http.StatusConflict {
		t.Fatalf("a credential nothing anchors was kept: %d", code)
	}

	seal := map[string]string{"i": cred.SAID, "s": "0", "d": cred.SAID}
	code, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"aid": aid, "t": "ixn", "a": []any{seal}, "after": map[string]string{"s": "0", "d": aid}})
	if code != http.StatusOK {
		t.Fatalf("prepare anchor: %d %v", code, out)
	}
	ixn := preparedBytes(t, out)
	code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(ixn), "sigs": []string{appSign(t, k[0], ixn, false)}})
	if code != http.StatusCreated {
		t.Fatalf("commit anchor: %d %v", code, out)
	}
	ixnSaid := out["d"].(string)

	// Another credential is not the one the interaction anchors.
	other, _, _ := s.KeriDriver.(credentialBuilder).BuildCredential(aid, map[string]interface{}{"name": "Eve"}, "Eschema", "Eholder", nil)
	if code, _ := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": base64.StdEncoding.EncodeToString(other), "ixn_said": ixnSaid}); code != http.StatusConflict {
		t.Fatalf("a credential the interaction does not anchor was kept: %d", code)
	}
	// A credential of somebody else's is not recorded as this identity's.
	foreign, _, _ := s.KeriDriver.(credentialBuilder).BuildCredential("Eelse", map[string]interface{}{"name": "Eve"}, "Eschema", "Eholder", nil)
	if code, _ := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": base64.StdEncoding.EncodeToString(foreign), "ixn_said": ixnSaid}); code != http.StatusBadRequest {
		t.Fatalf("another issuer's credential was kept: %d", code)
	}
	if cs, _ := s.DataStore.GetCredentialsFiltered("", ""); len(cs) != 0 {
		t.Fatalf("%d credentials kept before the right one was", len(cs))
	}

	code, out = call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": acdcB64, "ixn_said": ixnSaid})
	if code != http.StatusCreated || out["acdc_said"] != cred.SAID {
		t.Fatalf("record: %d %v", code, out)
	}
	kept, _ := s.DataStore.GetCredential(cred.SAID)
	if kept == nil || kept.IssuerAID != aid || kept.HolderAID != "Eholder" || kept.IxnSAID != ixnSaid {
		t.Fatalf("kept %+v", kept)
	}
	// Recorded again, it is kept once.
	if code, _ := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": acdcB64, "ixn_said": ixnSaid}); code != http.StatusOK {
		t.Fatalf("record twice: %d", code)
	}
}

// An interaction somebody stored without the key's signature is not in the key
// log, whatever it seals: nothing is kept on it and nothing is delivered.
func TestACredentialIsNotKeptOnAnAnchorTheKeyDidNotSign(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	_, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Mallory"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	acdcB64, said := out["acdc_json_b64"].(string), out["acdc_said"].(string)
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: aid, SN: 1,
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + said + `","s":"0","d":"` + said + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(ixn)
	record := func() int {
		code, _ := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
			"acdc_json_b64": acdcB64, "ixn_said": ev.SAID})
		return code
	}
	plant := func(sigs []string) {
		if err := s.DataStore.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: 1, EventType: "ixn",
			EventJSON: string(ixn), RawBytesB64: base64.StdEncoding.EncodeToString(ixn), Signatures: sigs}); err != nil {
			t.Fatal(err)
		}
	}
	// Stored as /api/store/event stores it: no signature at all.
	plant(nil)
	if code := record(); code != http.StatusConflict {
		t.Fatalf("a credential was kept on an unsigned interaction: %d", code)
	}
	// Signed, but by a key that is not the one the log is at (the next key).
	plant([]string{appSign(t, k[1], ixn, false)})
	if code := record(); code != http.StatusConflict {
		t.Fatalf("a credential was kept on an interaction another key signed: %d", code)
	}
	if cs, _ := s.DataStore.GetCredentialsFiltered("", ""); len(cs) != 0 {
		t.Fatalf("%d credentials kept", len(cs))
	}
	// Signed by the identity's key, the same bytes are an anchor.
	plant([]string{appSign(t, k[0], ixn, false)})
	if code := record(); code != http.StatusCreated {
		t.Fatalf("a credential a signed interaction anchors was refused: %d", code)
	}
}

// anchoredCredential prepares a credential, has the key anchor it, and returns
// what a record of it is sent.
func anchoredCredential(t *testing.T, s *CoreServer, aid string, k [][]byte) map[string]any {
	t.Helper()
	_, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	said := out["acdc_said"].(string)
	seal := map[string]string{"i": said, "s": "0", "d": said}
	_, prep := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"aid": aid, "t": "ixn", "a": []any{seal}, "after": map[string]string{"s": "0", "d": aid}})
	ixn := preparedBytes(t, prep)
	code, done := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(ixn), "sigs": []string{appSign(t, k[0], ixn, false)}})
	if code != http.StatusCreated {
		t.Fatalf("commit anchor: %d %v", code, done)
	}
	return map[string]any{"acdc_json_b64": out["acdc_json_b64"], "ixn_said": done["d"]}
}

// A credential recorded after it was revoked is answered as revoked, not as
// issued.
func TestARecordOfARevokedCredentialSaysItIsRevoked(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	body := anchoredCredential(t, s, aid, k)
	code, out := call(t, s, s.handleRecordCredential, "/api/credential/record", body)
	if code != http.StatusCreated || out["status"] != "issued" {
		t.Fatalf("record: %d %v", code, out)
	}
	said := out["acdc_said"].(string)
	if err := s.DataStore.UpdateCredentialStatus(said, "revoked"); err != nil {
		t.Fatal(err)
	}
	code, out = call(t, s, s.handleRecordCredential, "/api/credential/record", body)
	if code != http.StatusOK || out["status"] != "revoked" {
		t.Fatalf("a revoked credential was answered %d %v", code, out)
	}
}

// slowToLookUpCredentials is a store whose credential lookup takes a moment,
// so that two records of one credential overlap.
type slowToLookUpCredentials struct{ store.Store }

func (d slowToLookUpCredentials) GetCredential(said string) (*store.CredentialRecord, error) {
	r, err := d.Store.GetCredential(said)
	time.Sleep(50 * time.Millisecond)
	return r, err
}

// Records of one credential that arrive together keep it once: one answers that
// it was recorded, the rest that it already was.
func TestTwoRecordsOfOneCredentialKeepItOnce(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	body := anchoredCredential(t, s, aid, k)
	// What the anchoring started in the background has finished with the store
	// before it is swapped.
	s.background.wg.Wait()
	s.DataStore = slowToLookUpCredentials{s.DataStore}
	const records = 6
	codes := make(chan int, records)
	for i := 0; i < records; i++ {
		go func() {
			rec := httptest.NewRecorder()
			b, _ := json.Marshal(body)
			s.handleRecordCredential(rec, ownerRequest(http.MethodPost, "/api/credential/record", strings.NewReader(string(b)), s))
			codes <- rec.Code
		}()
	}
	created := 0
	for i := 0; i < records; i++ {
		if <-codes == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d records each kept the credential and sent it on", created)
	}
}

// plantSignedIxns stores n signed interactions after the tip, as a log kept for
// a long time is, and returns the last one's digest.
func plantSignedIxns(t *testing.T, s *CoreServer, aid string, k [][]byte, prior string, from, n int, data func(i int) []json.RawMessage) string {
	t.Helper()
	for i := 0; i < n; i++ {
		ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: prior, SN: from + i, Data: data(i)})
		if err != nil {
			t.Fatal(err)
		}
		ev, _ := keri.ParseEvent(ixn)
		if err := s.DataStore.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: from + i, EventType: "ixn",
			EventJSON: string(ixn), RawBytesB64: base64.StdEncoding.EncodeToString(ixn),
			Signatures: []string{appSign(t, k[0], ixn, false)}}); err != nil {
			t.Fatal(err)
		}
		prior = ev.SAID
	}
	return prior
}

// An identity that has issued thousands of credentials has a key log longer
// than a log somebody sends is judged at, and a credential it issues is still
// recorded: the length cap is for copies sent, not for the log kept here. The
// seal may also carry values that are not strings.
func TestACredentialIsKeptOnALogLongerThanASentLogMayBe(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	_, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	acdcSaid := out["acdc_said"].(string)
	tip := plantSignedIxns(t, s, aid, k, aid, 1, drivers.MaxLogEvents, func(int) []json.RawMessage {
		return []json.RawMessage{json.RawMessage(`{"d":"Efill"}`)}
	})
	// The seal beside others whose values are an array and an object.
	last := plantSignedIxns(t, s, aid, k, tip, drivers.MaxLogEvents+1, 1, func(int) []json.RawMessage {
		return []json.RawMessage{json.RawMessage(`{"i":"` + acdcSaid + `","s":"0","d":"` + acdcSaid + `","x":["a"],"y":{"b":1}}`)}
	})
	if evs, _ := s.DataStore.GetEvents(aid); len(evs) <= drivers.MaxLogEvents {
		t.Fatalf("the log has %d events, not more than a sent log may", len(evs))
	}
	code, got := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": out["acdc_json_b64"], "ixn_said": last})
	if code != http.StatusCreated {
		t.Fatalf("a credential a long log anchors was refused: %d %v", code, got)
	}
}

// A refusal says why: the history is unsigned, the interaction is not there,
// it seals something else, or the signature is not the key's.
func TestAnUnanchoredCredentialIsRefusedForTheReasonItIs(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	_, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	said := out["acdc_said"].(string)
	sealOf := func(d string) func(int) []json.RawMessage {
		return func(int) []json.RawMessage {
			return []json.RawMessage{json.RawMessage(`{"i":"` + d + `","s":"0","d":"` + d + `"}`)}
		}
	}
	reason := func(ixn string) string {
		code, got := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
			"acdc_json_b64": out["acdc_json_b64"], "ixn_said": ixn})
		if code != http.StatusConflict {
			t.Fatalf("refused with %d %v", code, got)
		}
		return got["error"].(string) + " " + got["details"].(string)
	}
	if r := reason("Enothere"); !strings.Contains(r, "holds no interaction with digest Enothere") {
		t.Fatalf("no interaction: %q", r)
	}
	other := plantSignedIxns(t, s, aid, k, aid, 1, 1, sealOf("Eother"))
	if r := reason(other); !strings.Contains(r, "does not seal that credential") {
		t.Fatalf("another seal: %q", r)
	}
	// Signed by the wrong key.
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: other, SN: 2,
		Data: sealOf(said)(0)})
	ev, _ := keri.ParseEvent(ixn)
	_ = s.DataStore.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: 2, EventType: "ixn", EventJSON: string(ixn),
		RawBytesB64: base64.StdEncoding.EncodeToString(ixn), Signatures: []string{appSign(t, k[1], ixn, false)}})
	if r := reason(ev.SAID); !strings.Contains(r, "does not verify") {
		t.Fatalf("wrong key: %q", r)
	}
}

// A key log with an event kept unsigned before the anchor is refused as such.
func TestAnAnchorAfterAnUnsignedEventIsRefusedAsUnsigned(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	_, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	said := out["acdc_said"].(string)
	first, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: aid, SN: 1,
		Data: []json.RawMessage{json.RawMessage(`{"d":"Efill"}`)}})
	fev, _ := keri.ParseEvent(first)
	_ = s.DataStore.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: 1, EventType: "ixn", EventJSON: string(first),
		RawBytesB64: base64.StdEncoding.EncodeToString(first)})
	last := plantSignedIxns(t, s, aid, k, fev.SAID, 2, 1, func(int) []json.RawMessage {
		return []json.RawMessage{json.RawMessage(`{"i":"` + said + `","s":"0","d":"` + said + `"}`)}
	})
	code, got := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": out["acdc_json_b64"], "ixn_said": last})
	if code != http.StatusConflict || !strings.Contains(got["details"].(string), "kept without its signed bytes") {
		t.Fatalf("unsigned history: %d %v", code, got)
	}
}

// A row kept before signatures were lists carries its one signature in
// CesrSignature, and reads as signed everywhere a stored log is read.
func TestAStoredLogIsReadWithTheSignatureAnOlderRowKeptItIn(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: aid, SN: 1,
		Data: []json.RawMessage{json.RawMessage(`{"d":"Efill"}`)}})
	if err := s.DataStore.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: 1, EventType: "ixn", EventJSON: string(ixn),
		RawBytesB64: base64.StdEncoding.EncodeToString(ixn), CesrSignature: appSign(t, k[0], ixn, false)}); err != nil {
		t.Fatal(err)
	}
	keys, err := s.ownKeysInForce(aid)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys in force from a legacy row: %v %v", keys, err)
	}
}

// A credential issued outside a registry is sealed {i: said, s: "0", d: said},
// and only that seal records it: one with no digest, or another, does not.
func TestACredentialIsKeptOnlyOnTheSealThatNamesItTwice(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	_, out := call(t, s, s.handlePrepareCredential, "/api/credential/prepare", map[string]any{
		"claims": map[string]any{"name": "Ada"}, "schema_said": "Eschema", "holder_aid": "Eholder"})
	said := out["acdc_said"].(string)
	prior := aid
	for n, seal := range []string{
		`{"i":"` + said + `","s":"0"}`,
		`{"i":"` + said + `","s":"0","d":"Eother"}`,
	} {
		ixn := plantSignedIxns(t, s, aid, k, prior, n+1, 1, func(int) []json.RawMessage {
			return []json.RawMessage{json.RawMessage(seal)}
		})
		code, got := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
			"acdc_json_b64": out["acdc_json_b64"], "ixn_said": ixn})
		if code != http.StatusConflict || !strings.Contains(got["details"].(string), "does not seal that credential") {
			t.Fatalf("a credential was kept on the seal %s: %d %v", seal, code, got)
		}
		prior = ixn
	}
	ixn := plantSignedIxns(t, s, aid, k, prior, 3, 1, func(int) []json.RawMessage {
		return []json.RawMessage{json.RawMessage(`{"i":"` + said + `","s":"0","d":"` + said + `"}`)}
	})
	if code, got := call(t, s, s.handleRecordCredential, "/api/credential/record", map[string]any{
		"acdc_json_b64": out["acdc_json_b64"], "ixn_said": ixn}); code != http.StatusCreated {
		t.Fatalf("the seal that names it twice was refused: %d %v", code, got)
	}
}

// A credential already kept is answered from what is kept, without judging the
// key log again, which costs work in the log's length on every record sent.
// The log is spoiled after it is kept, so judging it again would refuse.
func TestARecordOfAKeptCredentialDoesNotJudgeTheLogAgain(t *testing.T) {
	s, aid, k := foundedAppHeld(t)
	body := anchoredCredential(t, s, aid, k)
	if code, out := call(t, s, s.handleRecordCredential, "/api/credential/record", body); code != http.StatusCreated {
		t.Fatalf("record: %d %v", code, out)
	}
	s.background.wg.Wait()
	evs, _ := s.DataStore.GetEvents(aid)
	founding := evs[0]
	founding.Signatures = []string{appSign(t, k[1], []byte(founding.EventJSON), true)}
	if err := s.DataStore.SaveEvent(founding); err != nil {
		t.Fatal(err)
	}
	if err := s.keyLogAnchors(aid, body["ixn_said"].(string), ""); err == nil {
		t.Fatal("the spoiled log still verifies, so this test proves nothing")
	}
	if code, out := call(t, s, s.handleRecordCredential, "/api/credential/record", body); code != http.StatusOK || out["status"] != "issued" {
		t.Fatalf("a kept credential was judged again: %d %v", code, out)
	}
}
