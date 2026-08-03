package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"identity-agent-core/secureenclave"
)

// The hole this closes: a token authenticates whoever holds the string, not a
// machine. Anyone who read it out of a terminal or a config file could enrol a
// key of their own choosing — and the owner's KEL would then say the owner
// delegated to it.
func TestATokenAloneCannotEnrolSomebodyElsesKey(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token := issueToken(t, h, "the server", "host", "https://server.example")

	// The attacker has the token — the entire authentication before this change
	// — and a key they generated. What they do not have is the private half of
	// the key belonging to the machine the token was meant for.
	victim := newTestMachine(t)
	attacker := newTestMachine(t)

	w := enrolRaw(t, h, map[string]string{
		"token": token.Token, "public_key": victim.pub, "next_public_key": victim.next,
		// Signed with the attacker's key over the victim's key material: the
		// closest thing to a valid proof they can construct.
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(attacker.priv,
			[]byte(EnrolProofPayload(token.Token, victim.pub, victim.next)))),
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("an enrolment signed by the wrong key was accepted: %d %s", w.Code, w.Body)
	}

	// And the token must survive, or a stranger who cannot enrol can still deny
	// the real machine its enrolment by burning the token.
	if w := enrol(t, h, token.Token, victim); w.Code != http.StatusCreated {
		t.Fatalf("the legitimate machine could not enrol afterwards: %d %s", w.Code, w.Body)
	}
}

func TestAnEnrolmentWithNoSignatureIsRefused(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token := issueToken(t, h, "the server", "host", "")
	m := newTestMachine(t)

	w := enrolRaw(t, h, map[string]string{
		"token": token.Token, "public_key": m.pub, "next_public_key": m.next,
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("an unsigned enrolment was accepted: %d %s", w.Code, w.Body)
	}
}

// The next key is the pre-rotation commitment. Substituting it while leaving
// the current key alone would hand somebody the only key that can ever succeed
// this identity — so the proof has to cover it.
func TestTheProofCoversTheNextKeyToo(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token := issueToken(t, h, "the server", "host", "")
	m := newTestMachine(t)

	substitutePub, _, _ := ed25519.GenerateKey(rand.Reader)
	substitute := base64.RawURLEncoding.EncodeToString(substitutePub)

	w := enrolRaw(t, h, map[string]string{
		"token": token.Token, "public_key": m.pub,
		"next_public_key": substitute,
		// A signature the machine really did make — over its own next key, not
		// the substituted one.
		"signature": m.sign(token.Token),
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("the next key was swapped and the enrolment was accepted: %d %s", w.Code, w.Body)
	}
}

// The race the claim-under-lock exists for. Two machines with the same token
// must not both end up with an identity anchored in the owner's KEL — an
// anchored identity cannot be withdrawn, while a token can be reissued.
func TestTwoMachinesRacingOneTokenProduceOneIdentity(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	token := issueToken(t, h, "the server", "host", "")

	const racers = 8
	machines := make([]*testMachine, racers)
	for i := range machines {
		machines[i] = newTestMachine(t)
	}

	var wg sync.WaitGroup
	codes := make([]int, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = enrol(t, h, token.Token, machines[i]).Code
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for _, c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d of %d racers were issued an identity from one token; want exactly 1",
			created, racers)
	}

	// The stronger statement: count what was actually anchored, not what was
	// reported. A racer refused after its identity was already minted would
	// still show up here.
	if n := keri.anchorsIssued.Load(); n > 1 {
		t.Errorf("%d delegations were anchored in the owner's KEL from a single-use token",
			n)
	}
}

// A machine that cannot attest must still enrol — otherwise nothing can be
// enrolled until every machine has the hardware, and the pressure is then to
// fake a pass. But the record has to say so.
func TestAMachineWithNoAttestationEnrolsAndSaysSo(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token := issueToken(t, h, "the server", "host", "")
	m := newTestMachine(t)

	w := enrol(t, h, token.Token, m)
	if w.Code != http.StatusCreated {
		t.Fatalf("a machine without attestation could not enrol: %d %s", w.Code, w.Body)
	}

	out := decodeEnrolResponse(t, w)
	if out.Asset.MachineIDValue != "" || out.Asset.MachineIDKind != "" {
		t.Errorf("a machine that sent no attestation was recorded as identified: %+v", out.Asset)
	}
	if out.Asset.MachineIDWhy == "" {
		t.Error("no hardware identity was recorded and no reason was given")
	}
	if out.MachineWarning == "" {
		t.Error("the response did not warn that this machine has no hardware identity")
	}
}

// An attestation report that is not bound to the key being enrolled proves only
// that some sealed machine exists somewhere — including the attacker's own. It
// must not be recorded as identifying this one.
func TestAnUnboundAttestationIdentifiesNothing(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token := issueToken(t, h, "the server", "host", "")
	m := newTestMachine(t)

	// A structurally valid report bound to a DIFFERENT key.
	w := enrolRaw(t, h, map[string]string{
		"token": token.Token, "public_key": m.pub, "next_public_key": m.next,
		"signature":          m.sign(token.Token),
		"attestation_report": base64.StdEncoding.EncodeToString(reportBoundTo("some other key")),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("enrolment should still succeed, only unidentified: %d %s", w.Code, w.Body)
	}
	out := decodeEnrolResponse(t, w)
	if out.Asset.MachineIDValue != "" {
		t.Errorf("an unbound report was accepted as identifying this machine: %q",
			out.Asset.MachineIDValue)
	}
	if out.Asset.MachineIDWhy == "" {
		t.Error("an unbound report was rejected without saying why")
	}
}

// The whole point of the ceremony: the chip that enrolled is written down.
func TestABoundAttestationRecordsWhichMachine(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token := issueToken(t, h, "the server", "host", "")
	m := newTestMachine(t)

	w := enrolRaw(t, h, map[string]string{
		"token": token.Token, "public_key": m.pub, "next_public_key": m.next,
		"signature":          m.sign(token.Token),
		"attestation_report": base64.StdEncoding.EncodeToString(reportBoundTo(m.pub)),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("enrolment failed: %d %s", w.Code, w.Body)
	}
	out := decodeEnrolResponse(t, w)
	if out.Asset.MachineIDKind != "snp-chip-id" {
		t.Errorf("machine id kind = %q, want snp-chip-id", out.Asset.MachineIDKind)
	}
	if out.Asset.MachineIDValue == "" {
		t.Fatal("a bound report did not record which machine enrolled")
	}
	if out.MachineWarning != "" {
		t.Errorf("an identified machine was warned about: %q", out.MachineWarning)
	}
}

// --- helpers ---

type enrolResponse struct {
	Asset          Asset  `json:"asset"`
	MachineWarning string `json:"machine_warning"`
}

func decodeEnrolResponse(t *testing.T, w *httptest.ResponseRecorder) enrolResponse {
	t.Helper()
	var out enrolResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the enrolment response: %v", err)
	}
	return out
}

// reportBoundTo builds a structurally valid SEV-SNP report whose REPORT_DATA is
// the binding for value. Real hardware is not available in a unit test and this
// is not pretending to be it — the signature is not checked here, only the
// binding and the fields, which is exactly what this handler decides on.
func reportBoundTo(value string) []byte {
	r := make([]byte, secureenclave.ReportSize)
	copy(r[0x50:], secureenclave.BindReportData(value)) // REPORT_DATA
	for i := 0; i < secureenclave.ChipIDSize; i++ {
		r[0x1A0+i] = 0x5A // CHIP_ID — non-zero, or it reads as masked
	}
	for i := 0x2A0; i < secureenclave.ReportSize; i++ {
		r[i] = 0x7F // a signature must be present, though it is not verified here
	}
	return r
}
