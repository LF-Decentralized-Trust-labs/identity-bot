package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/endpointrecord"
	"identity-agent-core/internal/boundedread"
)

// Checking that what answers at an address holds the keys of the identity it
// names (ADR-062, "an address also shows it holds the keys").
//
// POST /api/verify/agent-at-address   {"address": "...", "aid": "..."?}
//
// WHY THE ASKING COMPUTER'S OWN CORE DOES THIS. A key history is public, so
// reading one from an address shows only that the address can copy a document:
// any host can replay it. What a host that is not the agent cannot do is sign a
// challenge with the keys the history commits to. The proof is made of two
// signatures, one of them ML-DSA-65, and this core is the one implementation
// of that check; an app asks it rather than carrying a second one.
//
// THE CHALLENGE IS MADE HERE, fresh for every call and never taken from the
// caller, so nothing the app is told can fix it in advance.
//
// WHAT IT ESTABLISHES, and no more: that whatever answered at this origin just
// now holds the keys the identifier has in force in a key log that checks out.
// It is not tied to later traffic (ADR-062 "Not covered"), which is why an
// address that carries a person's approval should also be https.
//
// aid is optional. A first connection does not know it yet and learns it from
// the answer; a later one names the identifier it remembered and gets a refusal
// if the address answers for another. Either way the history is read for the
// identifier the ANSWER names and then compared with the one asked for.

type agentAtAddressRequest struct {
	// Address is where the agent was dialled; its origin is what is signed for.
	Address string `json:"address"`
	// AID, when the caller already remembers which identifier this is.
	AID string `json:"aid"`
}

func (s *CoreServer) handleVerifyAnAgentAtAnAddress(w http.ResponseWriter, r *http.Request) {
	var req agentAtAddressRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}
	origin, err := endpointrecord.OriginOf(strings.TrimSpace(req.Address))
	if err != nil {
		writeError(w, http.StatusBadRequest, "say where the agent is, as an http or https address", err.Error())
		return
	}
	if s.KeriDriver == nil {
		writeError(w, http.StatusNotImplemented,
			"this computer has no key engine, so it cannot check who is at that address",
			"an identity that cannot be checked must not be acted on")
		return
	}
	aid, key, no := s.proveAnAgentAt(origin, strings.TrimSpace(req.AID))
	if no != nil {
		writeJSON(w, verifyIdentityResponse{Why: no.why, Kind: no.kind})
		return
	}
	writeJSON(w, verifyIdentityResponse{Verified: true, AID: aid, PublicKey: key})
}

// What kind of not-proved it is, because the two call for different words to a
// person. Nothing answering says nothing about who is there (a server that is
// down, a network that is off); something answering that cannot prove it holds
// the identity's keys is a different thing at that address.
const (
	KindNoAnswer     = "no-answer"
	KindDifferent    = "different"
	KindCouldNotTell = "could-not-tell"
)

type notProved struct{ why, kind string }

// proveAnAgentAt asks the agent at origin to sign a fresh challenge and checks
// the answer against the key history it publishes. It returns the identifier
// proved, or why it is not proved.
func (s *CoreServer) proveAnAgentAt(origin, wantAID string) (aid, key string, no *notProved) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", &notProved{why: "this computer could not make a fresh question to ask", kind: KindCouldNotTell}
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw) // 32 printable characters

	q := url.Values{"origin": {origin}, "challenge": {challenge}}
	if wantAID != "" {
		q.Set("aid", wantAID)
	}
	proofURL := origin + "/api/identity/proof?" + q.Encode()
	resp, err := s.chosenAddressClient(15*time.Second, proofURL).Get(proofURL)
	if err != nil {
		log.Printf("[agent-at-address] %s did not answer the proof: %v", origin, err)
		return "", "", &notProved{why: "nothing answered at that address", kind: KindNoAnswer}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[agent-at-address] %s answered the proof with %d", origin, resp.StatusCode)
		return "", "", &notProved{why: "what answers at that address did not prove it holds an identity's keys", kind: KindDifferent}
	}
	var proof didcomm.KeyProof
	if err := boundedread.Decode(resp.Body, 1<<20, &proof); err != nil {
		log.Printf("[agent-at-address] %s sent a proof that could not be read: %v", origin, err)
		return "", "", &notProved{why: "what answers at that address did not prove it holds an identity's keys", kind: KindDifferent}
	}
	aid = proof.DID.AID
	if aid == "" || (wantAID != "" && aid != wantAID) {
		return "", "", &notProved{why: "what answers at that address is not the identity this computer was connected to", kind: KindDifferent}
	}

	events, currentKey, why := s.verifiedKeyLogAt(aid, origin+"/oobi/"+aid)
	if why != "" {
		// A history that cannot be read is not the same as one that does not
		// check out: the first says nothing about who is there.
		kind := KindDifferent
		if strings.HasPrefix(why, "could not read the key history") {
			kind = KindNoAnswer
		}
		return "", "", &notProved{why: why, kind: kind}
	}
	if err := didcomm.CheckKeyProof(&proof, aid, origin, challenge, events, currentKey, time.Now()); err != nil {
		log.Printf("[agent-at-address] %s did not pass the proof for %s: %v", origin, aid, err)
		return "", "", &notProved{why: "what answers at that address could not prove it is the identity it names", kind: KindDifferent}
	}
	return aid, currentKey, nil
}
