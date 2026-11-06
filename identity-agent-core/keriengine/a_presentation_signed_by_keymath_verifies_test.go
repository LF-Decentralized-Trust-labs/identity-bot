package keriengine

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keymath"
)

// The signature an app hands back for a presentation is checked against a bare
// public key, so it is the unindexed form (keymath's ed25519_sig). The indexed
// form belongs on a key event judged against a key state and is refused here.
func TestAPresentationSignatureTheAppWritesIsTheOneThePresentationCheckReads(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	acdc, said, _, log := issuedTo(t, e, subject.AID)
	pres := presentedBy(t, e, subject, said, subject.AID)
	signed, err := base64.StdEncoding.DecodeString(pres.PresSaidB64)
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := subject.Signer.Sign(signed)
	if err != nil {
		t.Fatal(err)
	}
	write := func(op string) string {
		req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(rawSig)})
		out, err := keymath.Do(op, req)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Sig string `json:"sig_qb64"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		return got.Sig
	}
	verify := func(sig string) (*drivers.DriverVerifyCredentialResponse, error) {
		return e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
			AcdcJson: acdc, HolderAid: subject.AID, PresentationSaid: pres.PresSaidB64,
			PresentationBody: bodyOf(pres), CesrSignature: sig, HolderPublicKey: subject.Pub,
			HolderKelEvents: subject.KEL, RegistryEventsB64: log,
		})
	}

	unindexed := write("ed25519_sig")
	if !strings.HasPrefix(unindexed, "0B") {
		t.Fatalf("keymath wrote %q, not an unindexed signature", unindexed)
	}
	got, err := verify(unindexed)
	if err != nil || got.Checks["presentation"] != true {
		t.Fatalf("the unindexed signature was not accepted: %v %+v", err, got)
	}

	if _, err := verify(write("index_ed25519_sig")); err == nil {
		t.Fatal("an indexed signature was accepted off a key event")
	}
}
