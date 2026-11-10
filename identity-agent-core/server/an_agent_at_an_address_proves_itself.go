package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/endpoint"
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
// It is not tied to later traffic (ADR-062 "Not covered"), which is why plain
// http is refused here unless the host is this computer.
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
	// KnownSequence and KnownKey are the last key state this computer proved
	// for that identifier (the sequence number of the last event and the key it
	// put in force), when it has proved one. A history that ends earlier, or at
	// the same event with another key, is a rollback and is refused: an
	// identifier's log only moves forward, so a host that replays an older log
	// (with an old key it still holds) is not the agent at its present state.
	KnownSequence *int64 `json:"known_sequence,omitempty"`
	KnownKey      string `json:"known_key,omitempty"`
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
	// The proof is made for one origin and is not tied to the traffic that
	// follows, so over plain http it would show only that something answered
	// once, while anyone on the path could answer the rest. Plain http is
	// believed only where nobody is on the path: this computer itself.
	if strings.HasPrefix(origin, "http://") && !endpoint.IsLoopbackHost(hostOfOrigin(origin)) {
		writeJSON(w, verifyIdentityResponse{
			Why:  "that address is not secure (http), and only an https address, or one on this computer, can be checked",
			Kind: KindNotSecure,
		})
		return
	}
	if s.KeriDriver == nil {
		writeError(w, http.StatusNotImplemented,
			"this computer has no key engine, so it cannot check who is at that address",
			"an identity that cannot be checked must not be acted on")
		return
	}
	aid, key, seq, no := s.proveAnAgentAt(origin, strings.TrimSpace(req.AID), req.KnownSequence, req.KnownKey)
	if no != nil {
		writeJSON(w, verifyIdentityResponse{Why: no.why, Kind: no.kind})
		return
	}
	writeJSON(w, verifyIdentityResponse{Verified: true, AID: aid, PublicKey: key, Sequence: &seq})
}

// What kind of not-proved it is, because the two call for different words to a
// person. Nothing answering says nothing about who is there (a server that is
// down, a network that is off); something answering that cannot prove it holds
// the identity's keys is a different thing at that address.
const (
	KindNoAnswer     = "no-answer"
	KindDifferent    = "different"
	KindCouldNotTell = "could-not-tell"
	// KindNotSecure: plain http to a host that is not this computer. Nothing was
	// dialled; the address is refused for how it is written.
	KindNotSecure = "not-secure"
)

// hostOfOrigin is the host of an origin OriginOf wrote, without IPv6 brackets.
func hostOfOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

var anIdentifierShape = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)

type notProved struct{ why, kind string }

// proveAnAgentAt asks the agent at origin to sign a fresh challenge and checks
// the answer against the key history it publishes. It returns the identifier
// proved, or why it is not proved.
func (s *CoreServer) proveAnAgentAt(origin, wantAID string, knownSeq *int64, knownKey string) (aid, key string, seq int64, no *notProved) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", 0, &notProved{why: "this computer could not make a fresh question to ask", kind: KindCouldNotTell}
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
		return "", "", 0, &notProved{why: "nothing answered at that address", kind: KindNoAnswer}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[agent-at-address] %s answered the proof with %d", origin, resp.StatusCode)
		return "", "", 0, &notProved{why: "what answers at that address did not prove it holds an identity's keys", kind: KindDifferent}
	}
	var proof didcomm.KeyProof
	if err := boundedread.Decode(resp.Body, 1<<20, &proof); err != nil {
		log.Printf("[agent-at-address] %s sent a proof that could not be read: %v", origin, err)
		return "", "", 0, &notProved{why: "what answers at that address did not prove it holds an identity's keys", kind: KindDifferent}
	}
	aid = proof.DID.AID
	// The far side's own words go into a URL below: only an identifier's shape.
	if !anIdentifierShape.MatchString(aid) {
		return "", "", 0, &notProved{why: "what answers at that address named something that is not an identifier", kind: KindDifferent}
	}
	if aid == "" || (wantAID != "" && aid != wantAID) {
		return "", "", 0, &notProved{why: "what answers at that address is not the identity this computer was connected to", kind: KindDifferent}
	}

	events, currentKey, why := s.verifiedKeyLogAt(aid, origin+"/public/oobi/"+aid)
	if why != "" {
		// SOMETHING ANSWERED THE PROOF, so whatever goes wrong next is not
		// "nothing answered": a host that names an identifier and then refuses to
		// show its history is the far side choosing to look unreachable, and
		// treating that as a dropped network would let a swapped agent carry on
		// unnoticed. Only a failure to reach the proof route at all is no-answer.
		return "", "", 0, &notProved{why: why, kind: KindDifferent}
	}
	// The history is published as records that carry each event as text;
	// CheckKeyProof reads the events themselves.
	plainEvents := make([]map[string]interface{}, 0, len(events))
	for _, entry := range events {
		ev, err := eventFromKELEntry(entry)
		if err != nil {
			return "", "", 0, &notProved{why: err.Error(), kind: KindDifferent}
		}
		plainEvents = append(plainEvents, ev)
	}
	if err := didcomm.CheckKeyProof(&proof, aid, origin, challenge, plainEvents, currentKey, time.Now()); err != nil {
		log.Printf("[agent-at-address] %s did not pass the proof for %s: %v", origin, aid, err)
		return "", "", 0, &notProved{why: "what answers at that address could not prove it is the identity it names", kind: KindDifferent}
	}
	lastSeq, err := lastSequenceOf(plainEvents)
	if err != nil {
		return "", "", 0, &notProved{why: err.Error(), kind: KindDifferent}
	}
	if knownSeq != nil && (lastSeq < *knownSeq || (lastSeq == *knownSeq && knownKey != "" && currentKey != knownKey)) {
		log.Printf("[agent-at-address] %s showed %s's history at event %d, after this computer proved event %d", origin, aid, lastSeq, *knownSeq)
		return "", "", 0, &notProved{why: "what answers at that address shows an older history than this computer has already seen for that identity", kind: KindDifferent}
	}
	return aid, currentKey, lastSeq, nil
}

// lastSequenceOf is the sequence number of the last event of a log, read from
// the events themselves ("s", hexadecimal).
func lastSequenceOf(events []map[string]interface{}) (int64, error) {
	if len(events) == 0 {
		return 0, fmt.Errorf("that key history has no events")
	}
	raw, _ := events[len(events)-1]["s"].(string)
	n, err := strconv.ParseInt(raw, 16, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("the last event of that key history has no readable sequence number")
	}
	return n, nil
}
