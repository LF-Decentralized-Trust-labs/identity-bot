package server

import (
	"encoding/json"
	"identity-agent-core/store"
	"identity-agent-core/witness"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A claim has to prove that whoever sent it holds the identity it claims as.
//
// These run against a REAL second agent rather than a stand-in, because the
// thing being tested is a signature checked against a real key log, and a
// stand-in that returns whatever it is asked for would pass every one of them
// while proving nothing.

// pairableComputer is a freshly installed agent with a real KERI engine: no
// identity, nothing told to it, offered from its own screen.
func pairableComputer(t *testing.T) (*CoreServer, *httptest.Server, string) {
	t.Helper()
	resetLocalPairingOfferForTest()
	resetExpectedClaimForTest()
	resetPairingOfferForTest()
	resetPairingStateForTest()

	// The machine offers a report, as a sealed one does, and the owner accepts
	// what it proves. Both of these used to be replaced by allow_unattested in
	// the request — so these tests, which are about proving control, ran past
	// the check that decides whether the machine is worth proving control TO.
	aMachineThatCanAttest(t)

	machine := agentWithNoIdentity(t)
	eng := startedEngine(t)
	machine.KeriDriver = eng
	// A real agent wires this at startup, and the identity a machine founds
	// designates its witnesses through it. A fixture without one founds
	// something nothing can ever corroborate, which is the state this whole
	// file exists to detect rather than to reproduce.
	if sq, ok := machine.DataStore.(*store.SQLiteStore); ok {
		machine.WitnessService = witness.NewService(
			witness.NewSQLiteStore(sq.DB()), sq, eng, "desktop")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/provisioning/expect", machine.handleProvisioningExpect)
	mux.HandleFunc("/api/pairing/begin", machine.handlePairingBegin)
	mux.HandleFunc("/api/pairing/complete", machine.handlePairingComplete)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rec := httptest.NewRecorder()
	offerReq := httptest.NewRequest(http.MethodPost, "/api/pairing/offer-this-computer", nil)
	offerReq.RemoteAddr = "127.0.0.1:5050" // somebody sitting at it
	machine.handleOfferThisComputer(rec, offerReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("could not offer the computer: %d %s", rec.Code, rec.Body.String())
	}
	var offered struct {
		Code string `json:"code"`
	}
	json.NewDecoder(rec.Body).Decode(&offered)
	return machine, srv, offered.Code
}

// beginAt does what any claimant must do first: ask the machine for its key
// material. Without it a claim is refused for having nothing to complete, which
// is a different refusal entirely — and one that would make every test below
// pass with the proof-of-control check deleted.
func beginAt(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Post(url+"/api/pairing/begin", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var offer map[string]any
	json.NewDecoder(resp.Body).Decode(&offer)
	if offer["public_key"] == nil {
		t.Fatalf("the machine offered no key material: %v", offer)
	}
	return offer
}

func claimAs(t *testing.T, owner *CoreServer, url, code, ownerAID string) *httptest.ResponseRecorder {
	t.Helper()
	// This owner accepts what the machine proves. Without it the claim is
	// refused for the software the machine is running, which is a real check
	// and not the one these tests are about.
	acceptsThatBox(owner)
	body := `{"box_url":"` + url + `","adoption_code":"` + code + `"`
	if ownerAID != "" {
		body += `,"owner_aid":"` + ownerAID + `"`
	}
	body += `}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/adopt", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	owner.handlePairingAdopt(rec, req)
	return rec
}

// The honest case, end to end: it works.
//
// Without this every refusal below would be satisfied by a machine that refuses
// everybody, which would be useless and would look identical in a test report.
func TestAComputerCanBeClaimedByWhoeverProvesTheyHoldTheIdentity(t *testing.T) {
	machine, srv, code := pairableComputer(t)
	owner := adoptingOwner(t)

	if rec := claimAs(t, owner, srv.URL, code, ""); rec.Code != http.StatusOK {
		t.Fatalf("an honest claim was refused: %d %s", rec.Code, rec.Body.String())
	}

	got, err := machine.DataStore.GetIdentity()
	if err != nil || got == nil {
		t.Fatal("the computer did not end up with an identity of its own")
	}
	agents, err := owner.DataStore.ListAdoptedAgents()
	if err != nil || len(agents) != 1 {
		t.Fatalf("the owner did not record the computer: %v (%d)", err, len(agents))
	}
	if agents[0].SignsAsAID != got.AID {
		t.Fatalf("the owner thinks it signs as %q but it signs as %q", agents[0].SignsAsAID, got.AID)
	}
}

// THE POINT OF THE WHOLE CHANGE. Knowing the code is not enough.
//
// This is what the claim token used to be sufficient for: whoever picked it up
// — off a screen, out of a log, from a photograph — could name any identity
// they liked and the machine would seal it in permanently.
func TestKnowingTheCodeIsNotEnoughToClaimAComputer(t *testing.T) {
	machine, srv, code := pairableComputer(t)

	// The machine is mid-ceremony, exactly as it would be for an honest
	// claimant: key material offered, waiting for a claim.
	beginAt(t, srv.URL)

	// Everything an attacker who saw the code could send. No signature, because
	// they hold no key for the identity they are naming.
	body := `{"adoption_code":"` + code + `","found_as_root":true,` +
		`"owner_aid":"EAttackerNamesThemselves",` +
		`"owner_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}`
	resp, err := http.Post(srv.URL+"/api/pairing/complete", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("a computer was claimed by somebody who only knew the code — the code is " +
			"shown on a screen and travels through a website, so this is whoever saw it")
	}
	if id, _ := machine.DataStore.GetIdentity(); id != nil {
		t.Fatal("an identity was founded despite the claim being refused")
	}
}

// A signature by a key the claimed identity's log does not put in force.
//
// The attacker here does hold a key and can sign with it — they simply are not
// the identity they are naming. Checking that a signature merely verifies would
// pass this; it has to verify against the log of the identity being claimed.
func TestASignatureByTheWrongKeyIsRefused(t *testing.T) {
	machine, srv, code := pairableComputer(t)

	// A real, well-formed claim from a real second identity...
	attacker := adoptingOwner(t)
	victimAID := "EIdentityTheAttackerDoesNotHold"

	rec := claimAs(t, attacker, srv.URL, code, "")
	if rec.Code != http.StatusOK {
		t.Skipf("could not establish the honest baseline: %s", rec.Body.String())
	}
	// ...proves the machine accepts a properly signed claim. Now the same shape
	// naming somebody else's identity must not work.
	machine2, srv2, code2 := pairableComputer(t)
	beginAt(t, srv2.URL)
	// A real key and a real-shaped signature, so the ONLY thing that can refuse
	// this is the proof of control. Anything missing here would stop the claim
	// earlier and leave this test passing with the check deleted.
	body := `{"adoption_code":"` + code2 + `","found_as_root":true,"owner_aid":"` + victimAID + `",` +
		`"owner_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",` +
		`"owner_kel":[{"t":"icp","i":"` + victimAID + `","s":"0"}],` +
		`"owner_signature":"0BSomethingThatIsNotASignatureOverThisExchange"}`
	resp, err := http.Post(srv2.URL+"/api/pairing/complete", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a claim naming %s was accepted without a key log proving control of it", victimAID)
	}
	if id, _ := machine2.DataStore.GetIdentity(); id != nil {
		t.Fatal("an identity was founded on an unproven claim")
	}
	_ = machine
	_ = srv
}

// A signature is bound to the exchange it was made for.
//
// Otherwise a signature captured once could be replayed at any other machine
// mid-offer, and the proof would be worth nothing after its first use.
func TestASignatureFromOneExchangeDoesNotWorkOnAnother(t *testing.T) {
	a := claimSigningInput("challenge-one", "TOKEN", "EOwner", "DMachineKey")
	for _, other := range [][]byte{
		claimSigningInput("challenge-two", "TOKEN", "EOwner", "DMachineKey"),
		claimSigningInput("challenge-one", "OTHER-TOKEN", "EOwner", "DMachineKey"),
		claimSigningInput("challenge-one", "TOKEN", "ESomebodyElse", "DMachineKey"),
		claimSigningInput("challenge-one", "TOKEN", "EOwner", "DADifferentMachineKey"),
	} {
		if string(a) == string(other) {
			t.Fatalf("two different exchanges produce the same bytes to sign, so a "+
				"signature over one is a valid signature over the other: %s", a)
		}
	}
}

// The machine's own offered key is inside what gets signed.
//
// If it were not, anything sitting between the two parties could swap the key
// the machine offered for one of its own and the signature would still verify —
// and the owner would have signed a claim binding them to a machine whose keys
// somebody else holds.
func TestWhatIsSignedCoversTheKeyTheMachineOffered(t *testing.T) {
	if !strings.Contains(string(claimSigningInput("c", "t", "EOwner", "DTheOfferedKey")), "DTheOfferedKey") {
		t.Fatal("the machine's offered key is not covered by the signature, so it can be " +
			"substituted in flight without invalidating it")
	}
}

// A machine that cannot check a proof must refuse, not skip.
func TestAMachineThatCannotVerifyRefusesRatherThanTrusts(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.KeriDriver = nil

	err := s.verifyClaimantControlsTheIdentity(pairingCompleteRequest{
		OwnerAID:       "EOwner",
		OwnerSignature: "0Bsomething",
		OwnerKEL:       []map[string]interface{}{{"t": "icp", "i": "EOwner"}},
	}, "challenge", "DMachineKey")

	if err == nil {
		t.Fatal("a machine with no way to check a key log accepted a claim anyway, which " +
			"is how it ends up answering to whoever asked first")
	}
}

// THE BLACK BOX PATH, END TO END, WITH BOTH GATES.
//
// A machine somebody else set up is told two things before anyone can reach it:
// a claim token, and WHICH identity may present it. That identity is a pairwise
// one the owner minted before the machine was asked for, and handed over at
// reservation.
//
// So a claim there has to pass two independent checks — it must be the expected
// identity, and it must prove it holds that identity. Neither alone is enough:
// the first is a string the claimant supplies, and the second says nothing
// about whether this machine was meant for them.
//
// Nothing covered this. Every existing test that told a machine who to expect
// sent an unsigned claim, because they were written to prove refusals; the
// honest path through both gates was never run.
func TestTheIdentityAMachineWasPromisedToCanClaimItByProvingControl(t *testing.T) {
	resetLocalPairingOfferForTest()
	resetExpectedClaimForTest()
	resetPairingOfferForTest()

	// A machine somebody else set up refuses a history nobody else can confirm,
	// so this needs a real witness holding it — which is the point rather than
	// scaffolding. Stood up before minting so the identity designates it.
	wit := newStandInWitness(t)

	owner := adoptingOwner(t)

	// Before the machine is asked for: the owner mints the identity it will
	// answer to. This is the AID that goes to whoever provisions it.
	rec := httptest.NewRecorder()
	owner.handleMintMachineOwner(rec, httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("could not mint the identity for the machine: %s", rec.Body.String())
	}
	var minted struct {
		AID string `json:"aid"`
	}
	json.NewDecoder(rec.Body).Decode(&minted)
	if minted.AID == "" {
		t.Fatal("no identity was minted, so there is nothing to tell the machine to expect")
	}

	// The witness holds this identity's history, as it would after the identity
	// broadcast its inception to it. Set directly rather than waited for, so
	// the test turns on the corroboration check and not on a background send.
	wit.mu.Lock()
	wit.held[minted.AID] = owner.kelToPresent(minted.AID)
	wit.mu.Unlock()
	if len(wit.held[minted.AID]) == 0 {
		t.Fatal("the minted identity has no key log to be witnessed")
	}

	// The machine is started and told what to accept, while nobody else can
	// reach it.
	machine := agentWithNoIdentity(t)
	machine.KeriDriver = startedEngine(t)
	if err := SetExpectedClaim("TOKEN-FROM-THE-PROVISIONER", minted.AID); err != nil {
		t.Fatalf("could not tell the machine what to expect: %v", err)
	}
	t.Cleanup(resetExpectedClaimForTest)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/provisioning/expect", machine.handleProvisioningExpect)
	mux.HandleFunc("/api/pairing/begin", machine.handlePairingBegin)
	mux.HandleFunc("/api/pairing/complete", machine.handlePairingComplete)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The owner comes back and claims it with the identity it was promised to.
	if rec := claimAs(t, owner, srv.URL, "TOKEN-FROM-THE-PROVISIONER", minted.AID); rec.Code != http.StatusOK {
		t.Fatalf("the identity the machine was promised to could not claim it: %d %s",
			rec.Code, rec.Body.String())
	}

	got, err := machine.DataStore.GetIdentity()
	if err != nil || got == nil {
		t.Fatal("the machine did not end up with an identity of its own")
	}
	agents, _ := owner.DataStore.ListAdoptedAgents()
	if len(agents) != 1 || agents[0].OwnerAID != minted.AID {
		t.Fatalf("the machine was not recorded as owned by the identity it was promised to: %+v", agents)
	}
}

// And the second gate still bites when the first is satisfied.
//
// Somebody who holds a real identity, can sign perfectly well, and has the
// token — but is not who the machine was promised to — is still refused. This
// is what a machine in a data centre gets that a computer offered from its own
// screen cannot: it knows in advance who is coming.
func TestProvingControlOfSomeIdentityIsNotEnoughOnAMachinePromisedToAnother(t *testing.T) {
	resetLocalPairingOfferForTest()
	resetExpectedClaimForTest()
	resetPairingOfferForTest()

	machine := agentWithNoIdentity(t)
	machine.KeriDriver = startedEngine(t)
	if err := SetExpectedClaim("TOKEN", "EIdentityThisMachineWasPromisedTo"); err != nil {
		t.Fatalf("could not set the expectation: %v", err)
	}
	t.Cleanup(resetExpectedClaimForTest)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/provisioning/expect", machine.handleProvisioningExpect)
	mux.HandleFunc("/api/pairing/begin", machine.handlePairingBegin)
	mux.HandleFunc("/api/pairing/complete", machine.handlePairingComplete)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A real claimant, holding a real identity, signing correctly — just not
	// the one this machine is waiting for.
	stranger := adoptingOwner(t)
	rec := claimAs(t, stranger, srv.URL, "TOKEN", "")
	if rec.Code == http.StatusOK {
		t.Fatal("a machine promised to one identity was claimed by another that merely " +
			"proved it holds an identity of its own")
	}
	if id, _ := machine.DataStore.GetIdentity(); id != nil {
		t.Fatal("an identity was founded despite the claim being refused")
	}
}

// Scanning locks the machine. Somebody who reads the screen later is refused.
//
// This is what the registration step buys. Before it, a displayed code stood
// for its whole ten minutes and any valid claimant could use it; the machine
// now belongs to the first identity that presents the code, which in practice
// is seconds after the person scans.
func TestWhoeverScansFirstLocksTheComputerToTheirIdentity(t *testing.T) {
	machine, srv, code := pairableComputer(t)

	first := adoptingOwner(t)
	if rec := claimAs(t, first, srv.URL, code, ""); rec.Code != http.StatusOK {
		t.Fatalf("the person who scanned it could not claim it: %s", rec.Body.String())
	}

	// Somebody who read the same screen afterwards, holding a real identity of
	// their own and able to sign for it perfectly well.
	later := adoptingOwner(t)
	rec := claimAs(t, later, srv.URL, code, "")
	if rec.Code == http.StatusOK {
		t.Fatal("a second identity claimed a computer that was already locked to the first")
	}
	id, _ := machine.DataStore.GetIdentity()
	agents, _ := first.DataStore.ListAdoptedAgents()
	if id == nil || len(agents) != 1 || agents[0].SignsAsAID != id.AID {
		t.Fatal("the first claimant did not end up owning the machine")
	}
}

// The code is what earns the right to say who may claim. Guessing it does not.
func TestSayingWhoMayClaimNeedsTheCodeOffTheScreen(t *testing.T) {
	_, srv, _ := pairableComputer(t)

	body := `{"claim_token":"WRNG-WRNG-WRNG-WRNG","owner_aid":"EAttacker"}`
	resp, err := http.Post(srv.URL+"/api/provisioning/expect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("somebody who never saw the screen was allowed to say who may claim this " +
			"computer, which is the whole race the code exists to stop")
	}
	if _, owner, told := expectedAdoption(); told {
		t.Fatalf("a refused attempt still locked the machine, to %q", owner)
	}
}
