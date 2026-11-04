package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	keri "github.com/grapeid/keri-go"

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
