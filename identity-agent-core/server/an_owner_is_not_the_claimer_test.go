package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/login"
)

// The identity that claims a machine and the identity that owns what it founds
// are two different things, and the second is proved rather than asserted.
//
// ADR-038: whoever provisioned the machine was told which identity would claim
// it. Sealing that same identity as the owner would let them recognise their own
// customer in a published inception event — so an owner may be named separately.
// An owner named at inception can never be replaced, which is why naming one
// without proof is refused rather than trusted.

func TestNamingAnOwnerWithoutProvingItIsRefused(t *testing.T) {
	machine, _, _ := pairableComputer(t)

	for _, c := range []struct {
		what  string
		owner *foundedOwner
		says  string
	}{
		{
			"no identity at all",
			&foundedOwner{Signature: "x", KEL: []map[string]interface{}{{}}},
			"which identity",
		},
		{
			"an identity with no signature",
			&foundedOwner{AID: "EFakeOwner", KEL: []map[string]interface{}{{}}},
			"asserts control rather than proving it",
		},
		{
			"a signature with no key log to check it against",
			&foundedOwner{AID: "EFakeOwner", Signature: "sig"},
			"nothing to check",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := machine.verifyTheOwnerBeingSealed(c.owner, "EClaimer", "challenge", "code", "offered")
			if err == nil {
				t.Fatalf("%s was accepted as an owner; it would have been sealed into an "+
					"inception event that can never be rewritten", c.what)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Fatalf("refused, but not in words somebody could act on: %v", err)
			}
		})
	}
}

// A key log that does not prove its own authorship establishes nothing about who
// controls the identity, so it cannot support naming that identity as an owner.
func TestAnOwnerWhoseKeyLogProvesNothingIsRefused(t *testing.T) {
	machine, _, _ := pairableComputer(t)

	err := machine.verifyTheOwnerBeingSealed(&foundedOwner{
		AID:       "EDefinitelyNotARealIdentifier",
		Signature: "not-a-signature",
		KEL:       []map[string]interface{}{{"t": "icp", "i": "EDefinitelyNotARealIdentifier"}},
	}, "EClaimer", "challenge", "code", "offered")

	if err == nil {
		t.Fatal("an owner was sealed on a key log that proves nothing about who holds it")
	}
}

// A machine that cannot check a key log refuses, rather than sealing an owner it
// took on trust. Half a check is not a lesser version of the check.
func TestAMachineThatCannotCheckRefusesToSealAnOwner(t *testing.T) {
	machine, _, _ := pairableComputer(t)
	machine.KeriDriver = nil

	err := machine.verifyTheOwnerBeingSealed(&foundedOwner{
		AID:       "ESomeIdentity",
		Signature: "sig",
		KEL:       []map[string]interface{}{{"t": "icp"}},
	}, "EClaimer", "challenge", "code", "offered")

	if err == nil || !strings.Contains(err.Error(), "cannot verify a key log") {
		t.Fatalf("expected a refusal naming its own cause; got %v", err)
	}
}

// A claim that names no separate owner signs exactly what it always did.
//
// Every claimant already in use signs these bytes. Naming a separate owner
// changes what is signed only for a claim that names one.
func TestAClaimNamingNoSeparateOwnerSignsWhatItAlwaysDid(t *testing.T) {
	const always = `{"challenge":"c","claim_token":"t","machine_public_key":"DKey","owner_aid":"EClaimer"}`
	if got := string(claimSigningInput("c", "t", "EClaimer", "DKey")); got != always {
		t.Fatalf("a claim naming no separate owner now signs different bytes, so every "+
			"claimant in use is refused:\n got %s\nwant %s", got, always)
	}
}

// When a claim names a separate owner, the claimant signs for that owner and the
// owner signs as an owner, for that claimant.
//
// Written out, because these are what another implementation has to produce,
// and compared with one another, because a signature over one must never be a
// signature over another.
func TestWhatEachPartySignsWhenASeparateOwnerIsNamed(t *testing.T) {
	plain := string(claimSigningInput("c", "t", "EClaimer", "DKey"))
	claim := string(claimNamingAnOwnerSigningInput("c", "t", "EClaimer", "DKey", "EOwner"))
	owner := string(foundedOwnerSigningInput("c", "t", "EClaimer", "DKey", "EOwner"))

	if want := `{"challenge":"c","claim_token":"t","founded_owner_aid":"EOwner","machine_public_key":"DKey","owner_aid":"EClaimer"}`; claim != want {
		t.Fatalf("the claimant signs\n     %s\nwant %s", claim, want)
	}
	if want := `{"challenge":"c","claim_token":"t","claimer_aid":"EClaimer","founded_owner_aid":"EOwner","machine_public_key":"DKey","role":"founded_owner"}`; owner != want {
		t.Fatalf("the owner signs\n     %s\nwant %s", owner, want)
	}

	for what, pair := range map[string][2]string{
		"a claim naming an owner and one naming none": {claim, plain},
		"a claim and the owner it names":              {claim, owner},
		"a claim for one owner and for another": {claim,
			string(claimNamingAnOwnerSigningInput("c", "t", "EClaimer", "DKey", "EAnother"))},
		"an owner agreeing to one claimant and to another": {owner,
			string(foundedOwnerSigningInput("c", "t", "ESomebodyElse", "DKey", "EOwner"))},
		// An identity naming itself: what it signs as claimant is still not
		// what it signs as owner.
		"an identity as claimant and as its own owner": {
			string(claimNamingAnOwnerSigningInput("c", "t", "ESame", "DKey", "ESame")),
			string(foundedOwnerSigningInput("c", "t", "ESame", "DKey", "ESame"))},
	} {
		if pair[0] == pair[1] {
			t.Errorf("%s sign the same bytes, so a signature over one is a signature "+
				"over the other: %s", what, pair[0])
		}
	}
}

// aClaim is a claim part-way through: the machine has been told which identity
// may claim it and has offered its key material, and the claimant holds that
// identity. What is left for a test to decide is who the claim names as owner.
type aClaim struct {
	claimant   *CoreServer
	claimerAID string
	claimerIdx int
	code       string
	challenge  string
	offered    string
	// naming nobody: the claimant is the owner, signed as it always was.
	namingNobody pairingCompleteRequest
}

// signedWithAPairwiseKeyOf signs with one of an Identity Agent's own pairwise keys.
func signedWithAPairwiseKeyOf(t *testing.T, holder *CoreServer, idx int, input []byte) string {
	t.Helper()
	seed, err := holder.pairwiseSigningSeed(idx)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := login.SignString(string(input), seed)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// theClaimOf builds the claim of an identity the machine already expects.
func theClaimOf(t *testing.T, claimant *CoreServer, claimerAID string, claimerIdx int, url, code string) *aClaim {
	t.Helper()
	offer := beginAt(t, url)
	c := &aClaim{claimant: claimant, claimerAID: claimerAID, claimerIdx: claimerIdx, code: code}
	c.challenge, _ = offer["challenge"].(string)
	c.offered, _ = offer["public_key"].(string)

	claimerKey, err := claimant.pairwisePublicKey(claimerIdx)
	if err != nil {
		t.Fatal(err)
	}
	claimerSig, err := claimant.signClaim(claimerIdx, c.challenge, code, claimerAID, c.offered)
	if err != nil {
		t.Fatal(err)
	}
	c.namingNobody = pairingCompleteRequest{
		AdoptionCode:   code,
		FoundAsRoot:    true,
		OwnerAID:       claimerAID,
		OwnerPublicKey: claimerKey,
		OwnerKEL:       claimant.kelToPresent(claimerAID),
		OwnerSignature: claimerSig,
	}
	return c
}

// aClaimThatProvesItsClaimer takes a computer offered from its own screen to
// the point where everything about the claim itself is in order.
func aClaimThatProvesItsClaimer(t *testing.T, claimant *CoreServer, url, code string) *aClaim {
	t.Helper()
	claimerAID, _, _, claimerIdx, err := claimant.mintPairwiseIn("machines", "claims-the-machine")
	if err != nil {
		t.Fatalf("could not mint the identity that claims the machine: %v", err)
	}
	told, err := http.Post(url+"/api/provisioning/expect", "application/json", bytes.NewReader(
		mustJSON(t, map[string]string{"claim_token": code, "owner_aid": claimerAID})))
	if err != nil {
		t.Fatal(err)
	}
	told.Body.Close()
	if told.StatusCode != http.StatusOK {
		t.Fatalf("could not tell the machine who may claim it: %d", told.StatusCode)
	}
	return theClaimOf(t, claimant, claimerAID, claimerIdx, url, code)
}

// naming is the claim with a separate owner, the claimant having signed for
// that owner.
func (c *aClaim) naming(t *testing.T, owner *foundedOwner) pairingCompleteRequest {
	t.Helper()
	req := c.namingNobody
	req.FoundedOwner = owner
	req.OwnerSignature = signedWithAPairwiseKeyOf(t, c.claimant, c.claimerIdx,
		claimNamingAnOwnerSigningInput(c.challenge, c.code, c.claimerAID, c.offered, owner.AID))
	return req
}

// whatAnOwnerSigns is what an identity signs to be named as owner in this claim.
func (c *aClaim) whatAnOwnerSigns(ownerAID string) []byte {
	return foundedOwnerSigningInput(c.challenge, c.code, c.claimerAID, c.offered, ownerAID)
}

// anOwnerHeldBy is a second identity of holder's, with everything that proves
// it as the owner in this claim: its key, its key log, and its signature as
// owner by the key that log puts in force.
func (c *aClaim) anOwnerHeldBy(t *testing.T, holder *CoreServer, name string) *foundedOwner {
	t.Helper()
	aid, _, _, idx, err := holder.mintPairwiseIn("machines", name)
	if err != nil {
		t.Fatalf("could not mint the identity that owns what is founded: %v", err)
	}
	key, err := holder.pairwisePublicKey(idx)
	if err != nil {
		t.Fatal(err)
	}
	return &foundedOwner{
		AID:       aid,
		PublicKey: key,
		KEL:       holder.kelToPresent(aid),
		Signature: signedWithAPairwiseKeyOf(t, holder, idx, c.whatAnOwnerSigns(aid)),
	}
}

func completeWith(t *testing.T, url string, req pairingCompleteRequest) (int, string) {
	t.Helper()
	resp, err := http.Post(url+"/api/pairing/complete", "application/json", bytes.NewReader(mustJSON(t, req)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	return resp.StatusCode, body.String()
}

// refusedAndNothingFounded is what every refusal here has to leave behind: the
// answer asked for, and a machine with no identity and no owner.
func refusedAndNothingFounded(t *testing.T, machine *CoreServer, what string, status int, body string, want int, says string) {
	t.Helper()
	// The answer to a claim that succeeds is long, so only a refusal is quoted.
	if status == http.StatusOK {
		t.Fatalf("%s was accepted, and an identity was founded on it", what)
	}
	if id, _ := machine.DataStore.GetIdentity(); id != nil {
		t.Fatalf("%s was refused, and an identity was founded all the same", what)
	}
	if sealed, _ := machine.sealedOwnerAuthority(); sealed != nil {
		t.Fatalf("%s was refused, and %s was sealed as owner all the same", what, sealed.AID)
	}
	if status != want || !strings.Contains(body, says) {
		t.Fatalf("%s was refused, but not as %d saying %q: %d %s", what, want, says, status, body)
	}
}

// theOwnersNamedBy reads who the inception of what a machine founded names.
func theOwnersNamedBy(t *testing.T, machine *CoreServer) map[string]bool {
	t.Helper()
	founded, err := machine.DataStore.GetIdentity()
	if err != nil || founded == nil {
		t.Fatal("the machine did not end up with an identity of its own")
	}
	events, err := machine.DataStore.GetEvents(founded.AID)
	if err != nil || len(events) == 0 {
		t.Fatalf("the founded identity has no inception to read: %v", err)
	}
	var inception struct {
		Anchors []struct {
			I string `json:"i"`
		} `json:"a"`
	}
	if err := json.Unmarshal([]byte(events[0].EventJSON), &inception); err != nil {
		t.Fatalf("the inception cannot be read: %v", err)
	}
	named := map[string]bool{}
	for _, a := range inception.Anchors {
		named[a.I] = true
	}
	return named
}

// foundedOwnedBy checks that the machine founded an identity whose inception
// names the owner and not the claimer, and that it answers to that owner.
func foundedOwnedBy(t *testing.T, machine *CoreServer, claimerAID string, owner *foundedOwner) {
	t.Helper()
	named := theOwnersNamedBy(t, machine)
	if !named[owner.AID] {
		t.Fatalf("the inception does not name the proved owner %s: %v", owner.AID, named)
	}
	if named[claimerAID] {
		t.Fatalf("the inception names the identity that claimed the machine, which is "+
			"what a separate owner exists to keep out of it: %v", named)
	}
	sealed, err := machine.sealedOwnerAuthority()
	if err != nil || sealed.AID != owner.AID || sealed.PublicKey != owner.PublicKey {
		t.Fatalf("the machine does not answer to the proved owner: %+v (%v)", sealed, err)
	}
}

// A claimant who proves its own identity still cannot have a machine found
// something owned by an identity it does not hold.
//
// Everything about the claim itself is genuine here, and the claimant has
// signed for the owner it names, so the only thing that can refuse it is the
// proof asked of the owner. The owner named is a real identity with a real key,
// held by somebody else: exactly what a claimant would name to put another
// party's identity into an inception that can never be rewritten.
func TestAClaimNamingAnOwnerItDoesNotHoldFoundsNothing(t *testing.T) {
	someoneElse := adoptingOwner(t)
	theirAID, _, _, theirIdx, err := someoneElse.mintPairwiseIn("machines", "held-by-someone-else")
	if err != nil {
		t.Fatalf("could not mint the identity the claimant does not hold: %v", err)
	}
	theirKey, err := someoneElse.pairwisePublicKey(theirIdx)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		what  string
		owner func(claim *aClaim) *foundedOwner
		says  string
	}{
		{
			"an owner named with no signature and no key log",
			func(*aClaim) *foundedOwner {
				return &foundedOwner{AID: theirAID, PublicKey: theirKey}
			},
			"asserts control rather than proving it",
		},
		{
			// The owner's genuine key log, which is public, and a signature
			// over exactly what that owner would sign. Made by a key of the
			// claimant's, because the owner's is the one thing the claimant
			// lacks.
			"an owner whose key log is genuine but whose signature the claimant made",
			func(claim *aClaim) *foundedOwner {
				_, _, _, idx, err := claim.claimant.mintPairwiseIn("machines", "a-key-the-claimant-does-hold")
				if err != nil {
					t.Fatal(err)
				}
				return &foundedOwner{
					AID:       theirAID,
					PublicKey: theirKey,
					KEL:       someoneElse.kelToPresent(theirAID),
					Signature: signedWithAPairwiseKeyOf(t, claim.claimant, idx, claim.whatAnOwnerSigns(theirAID)),
				}
			},
			"does not hold that identity",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			aMachineThatMayFound(t)
			machine, srv, code := pairableComputer(t)
			claim := aClaimThatProvesItsClaimer(t, adoptingOwner(t), srv.URL, code)

			status, body := completeWith(t, srv.URL, claim.naming(t, c.owner(claim)))
			refusedAndNothingFounded(t, machine, c.what, status, body, http.StatusForbidden, c.says)
		})
	}
}

// The honest case: an owner that is proved is the owner that is named.
//
// Without this the refusals here would be satisfied by a machine that refuses
// every separate owner, which would leave no way to keep the claiming identity
// out of what the machine founds.
func TestAClaimNamingAnOwnerItProvesFoundsAnIdentityOwnedByIt(t *testing.T) {
	aMachineThatMayFound(t)
	machine, srv, code := pairableComputer(t)
	claimant := adoptingOwner(t)
	claim := aClaimThatProvesItsClaimer(t, claimant, srv.URL, code)

	// A second identity of the claimant's own, proved with the same evidence as
	// the claim: its key log, and a signature by the key that log puts in force.
	owner := claim.anOwnerHeldBy(t, claimant, "owns-what-is-founded")

	if status, body := completeWith(t, srv.URL, claim.naming(t, owner)); status != http.StatusOK {
		t.Fatalf("an owner that proved itself was refused: %d %s", status, body)
	}
	foundedOwnedBy(t, machine, claim.claimerAID, owner)
}

// An owner that proves itself but offers no key is refused before anything is
// founded.
//
// The key is what the machine checks its owner's signatures against. Founding
// first and finding the key missing afterwards would leave an identity that
// names an owner nobody can act as, on a machine that refuses to be claimed
// again.
func TestAProvedOwnerNamedWithoutItsKeyFoundsNothing(t *testing.T) {
	aMachineThatMayFound(t)
	machine, srv, code := pairableComputer(t)
	claimant := adoptingOwner(t)
	claim := aClaimThatProvesItsClaimer(t, claimant, srv.URL, code)

	// Everything that proves the owner, and no key to seal.
	owner := claim.anOwnerHeldBy(t, claimant, "owns-what-is-founded")
	owner.PublicKey = ""

	status, body := completeWith(t, srv.URL, claim.naming(t, owner))
	refusedAndNothingFounded(t, machine, "a proved owner whose key was never offered",
		status, body, http.StatusBadRequest, "founded_owner.public_key")
}

// A key that an identity has rotated away from does not make its holder that
// identity's owner-to-be.
//
// The owner named here is somebody else's identity. The claimant holds a key
// that identity once used, shows the key log as it stood before the rotation
// that retired it, and signs with the old key. All of that verifies on its own.
// A witness the log designates holds the rotation, and that is what refuses it.
func TestAnOwnerProvedWithAKeyItsIdentityRetiredFoundsNothing(t *testing.T) {
	aMachineThatMayFound(t)
	wit := newStandInWitness(t)
	machine, srv, code := pairableComputer(t)
	claim := aClaimThatProvesItsClaimer(t, adoptingOwner(t), srv.URL, code)

	theirs := newRotatingControllerWitnessedBy(t, "held-by-someone-else", wit.key)
	wit.mu.Lock()
	wit.held[theirs.aid] = []map[string]interface{}{inceptionRecordOf(theirs), signedRotation(t, theirs)}
	wit.mu.Unlock()
	retiredKey, _ := theirs.signers[0].PublicKey()

	owner := &foundedOwner{
		AID:       theirs.aid,
		PublicKey: retiredKey,
		KEL:       []map[string]interface{}{inceptionRecordOf(theirs)},
		Signature: sign(t, theirs.signers[0], claim.whatAnOwnerSigns(theirs.aid)),
	}
	status, body := completeWith(t, srv.URL, claim.naming(t, owner))
	refusedAndNothingFounded(t, machine, "an owner proved with a key its identity had retired",
		status, body, http.StatusForbidden, "not the whole history")
}

// A machine somebody else set up holds a separately named owner's history to
// what it holds the claimant's: somebody other than the presenter confirms it.
//
// Such a machine can always reach a witness, so a history no witness confirms
// is refused there. The claimant's history is confirmed in both cases below.
// Only the owner's differs, so only the owner's can be what decides.
func TestAHostedMachineFoundsOnlyForAnOwnerAWitnessCorroborates(t *testing.T) {
	for _, c := range []struct {
		what         string
		corroborated bool
	}{
		{"an owner whose history no witness confirms", false},
		{"an owner whose history a witness confirms", true},
	} {
		t.Run(c.what, func(t *testing.T) {
			aMachineThatMayFound(t)
			resetLocalPairingOfferForTest()
			resetExpectedClaimForTest()
			resetPairingOfferForTest()
			resetPairingStateForTest()
			t.Cleanup(func() {
				resetExpectedClaimForTest()
				resetPairingOfferForTest()
				resetPairingStateForTest()
			})

			// Stood up before anything is minted, so each identity designates it.
			wit := newStandInWitness(t)
			aMachineThatCanAttest(t)
			claimant := adoptingOwner(t)
			confirm := func(aid string) {
				wit.mu.Lock()
				wit.held[aid] = claimant.kelToPresent(aid)
				wit.mu.Unlock()
				wit.receipts(t, aid)
			}

			claimerAID, _, _, claimerIdx, err := claimant.mintPairwiseIn("machines", "claims-the-machine")
			if err != nil {
				t.Fatal(err)
			}
			confirm(claimerAID)

			// Told what to accept by whoever set it up, and never offered from
			// its own screen: a hosted machine.
			machine := agentWithNoIdentity(t)
			machine.KeriDriver = startedEngine(t)
			if err := SetExpectedClaim("TOKEN-FROM-THE-PROVISIONER", claimerAID); err != nil {
				t.Fatal(err)
			}
			if !machine.mustBeCorroborated() {
				t.Fatal("this machine is not one that refuses an unconfirmed history, so the test would prove nothing")
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/api/pairing/begin", machine.handlePairingBegin)
			mux.HandleFunc("/api/pairing/complete", machine.handlePairingComplete)
			srv := httptest.NewServer(mux)
			defer srv.Close()

			claim := theClaimOf(t, claimant, claimerAID, claimerIdx, srv.URL, "TOKEN-FROM-THE-PROVISIONER")
			owner := claim.anOwnerHeldBy(t, claimant, "owns-what-is-founded")
			if c.corroborated {
				confirm(owner.AID)
			}

			status, body := completeWith(t, srv.URL, claim.naming(t, owner))
			if c.corroborated {
				if status != http.StatusOK {
					t.Fatalf("an owner a witness confirmed was refused: %d %s", status, body)
				}
				foundedOwnedBy(t, machine, claimerAID, owner)
				return
			}
			refusedAndNothingFounded(t, machine, c.what, status, body, http.StatusForbidden,
				"could confirm "+owner.AID+"'s history")
		})
	}
}

// Nobody between the claimant and the machine can put a different owner into a
// claim, and the claim it was made from still works afterwards.
//
// The replacement is as good as an owner can be: a real identity, its real key
// log, and its own signature as owner in this very claim. What refuses it is
// that the claimant signed for the owner it chose, and this is not that owner.
//
// Then the claim as the claimant made it is sent to the same offer and founds,
// so a refusal costs the rightful claimant nothing.
func TestAnOwnerSwappedIntoAClaimIsRefusedAndTheClaimStillWorks(t *testing.T) {
	aMachineThatMayFound(t)
	machine, srv, code := pairableComputer(t)
	claimant := adoptingOwner(t)
	claim := aClaimThatProvesItsClaimer(t, claimant, srv.URL, code)

	chosen := claim.anOwnerHeldBy(t, claimant, "owns-what-is-founded")
	genuine := claim.naming(t, chosen)

	swapped := genuine
	swapped.FoundedOwner = claim.anOwnerHeldBy(t, adoptingOwner(t), "put-there-by-somebody-in-between")

	status, body := completeWith(t, srv.URL, swapped)
	refusedAndNothingFounded(t, machine, "a claim whose owner was replaced on the way",
		status, body, http.StatusForbidden, "This claim does not prove who is making it")

	if status, body := completeWith(t, srv.URL, genuine); status != http.StatusOK {
		t.Fatalf("after a refusal, the claim as the claimant made it no longer works "+
			"against the same offer: %d %s", status, body)
	}
	foundedOwnedBy(t, machine, claim.claimerAID, chosen)
}

// Nobody between the claimant and the machine can take the owner out of a claim.
//
// With the owner removed the claiming identity would be sealed as owner, which
// is the one outcome naming a separate owner exists to prevent. The claimant
// signed for an owner, so a claim arriving without one is not what it signed.
func TestAClaimWithItsOwnerRemovedIsRefused(t *testing.T) {
	aMachineThatMayFound(t)
	machine, srv, code := pairableComputer(t)
	claimant := adoptingOwner(t)
	claim := aClaimThatProvesItsClaimer(t, claimant, srv.URL, code)

	stripped := claim.naming(t, claim.anOwnerHeldBy(t, claimant, "owns-what-is-founded"))
	stripped.FoundedOwner = nil

	status, body := completeWith(t, srv.URL, stripped)
	refusedAndNothingFounded(t, machine, "a claim whose owner was removed on the way",
		status, body, http.StatusForbidden, "This claim does not prove who is making it")
}

// What an identity signs as claimant is not proof of it as an owner.
//
// The claimant names itself as the separate owner and offers its claim's own
// signature and key log as the owner's. Both are genuine. An owner signs as an
// owner, though, and this signature was made as a claimant.
func TestAClaimsOwnSignatureIsNotProofOfAnOwner(t *testing.T) {
	aMachineThatMayFound(t)
	machine, srv, code := pairableComputer(t)
	claim := aClaimThatProvesItsClaimer(t, adoptingOwner(t), srv.URL, code)

	itself := &foundedOwner{
		AID:       claim.claimerAID,
		PublicKey: claim.namingNobody.OwnerPublicKey,
		KEL:       claim.namingNobody.OwnerKEL,
	}
	req := claim.naming(t, itself)
	itself.Signature = req.OwnerSignature

	status, body := completeWith(t, srv.URL, req)
	refusedAndNothingFounded(t, machine, "a claim's own signature offered as its owner's",
		status, body, http.StatusForbidden, "This claim does not prove who would own what is founded")
}
