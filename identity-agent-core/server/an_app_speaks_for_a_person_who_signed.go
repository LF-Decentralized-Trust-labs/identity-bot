package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/trail"
)

// An app's back end speaks for a person it serves (browser -> app -> core,
// ADR-006, ADR-066, ADR-067).
//
// A browser never reaches this core. The person's browser talks to the app, and
// the app's back end, an enrolled machine bound to the app's asset
// (ControllerGrant.AppAsset), talks to the core with the request it signs as any
// controller's (a_request_from_a_controller.go). To speak FOR a person it adds,
// in headers so the signed body stays the words alone:
//
//	X-IA-Speaking-For      the person, by their identifier at the app's asset
//	X-IA-Person-Statement  the statement the person's browser key signed over a
//	                       salted fingerprint of the words (ADR-067): base64url
//	                       of the JSON agentmessage.PersonProof
//	X-IA-Person-Salt       the salt of that fingerprint, base64url
//
// The app's signature says the app asked. The person's says the person spoke.
// Both are needed, and an app machine that sends neither is refused: it has no
// one of its own to speak as. Who the app may speak for is whoever the asset
// admits now, not one person its grant names. Whose a key is comes from the
// person's own sign-in, which the core recorded itself (a_browsers_key_...go),
// and one function reads a statement as a person's, trail.CheckAuthor, which is
// the one the trail's Write runs.
const (
	headerSpeakingFor     = "X-IA-Speaking-For"
	headerPersonStatement = "X-IA-Person-Statement"
	headerPersonSalt      = "X-IA-Person-Salt"
)

// ThePersonStatementThatSpoke is the person's own signed statement a request
// carried, as sent, when the request was an app speaking for a person, and the
// salt of its fingerprint: what trail.Write takes beside the words.
func ThePersonStatementThatSpoke(proof *coretypes.ControllerProof) (agentmessage.PersonProof, []byte, bool) {
	if proof == nil || len(proof.PersonStatement) == 0 {
		return agentmessage.PersonProof{}, nil, false
	}
	var p agentmessage.PersonProof
	if json.Unmarshal(proof.PersonStatement, &p) != nil {
		return agentmessage.PersonProof{}, nil, false
	}
	return p, proof.PersonSalt, true
}

// theWordsAPersonSays is what a request carrying a person's words says, read
// the way the route reads it: the words, and the conversation, kind, recipient,
// reply and message id the person's statement must name. Only the route that
// carries a person's words to an AI agent is one a person speaks on.
func theWordsAPersonSays(r *http.Request, body []byte) (words []byte, m agentmessage.PersonMessage, err error) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method != http.MethodPost || len(parts) != 5 || parts[0] != "api" || parts[1] != "mcp" ||
		parts[2] != "agents" || parts[3] == "" || parts[4] != "conversations" {
		return nil, m, errors.New("an app speaks for a person only to put their words to an AI agent, " +
			"which is the one thing a person signs a statement for here")
	}
	if json.Unmarshal(body, &m) != nil {
		return nil, m, errors.New("the message must be JSON")
	}
	return []byte(m.Body), m, nil
}

// thePersonAnAppSpeaksFor settles who an app machine speaks for. A machine
// bound to no app speaks as the signer it belongs to, as it always has, and is
// refused if it names anyone. A machine bound to an app speaks for a person
// only, and only when every check below holds.
func (s *CoreServer) thePersonAnAppSpeaksFor(r *http.Request, grant ControllerGrant, body []byte) (named coretypes.Signer, statement, salt []byte, speaking bool, err error) {
	who := strings.TrimSpace(r.Header.Get(headerSpeakingFor))
	raw := strings.TrimSpace(r.Header.Get(headerPersonStatement))
	rawSalt := strings.TrimSpace(r.Header.Get(headerPersonSalt))
	refuse := func(e error) (coretypes.Signer, []byte, []byte, bool, error) {
		return coretypes.Signer{}, nil, nil, true, e
	}
	if grant.AppAsset == "" {
		if who == "" && raw == "" && rawSalt == "" {
			return coretypes.Signer{}, nil, nil, false, nil
		}
		return refuse(errors.New("this machine is not the back end of an app, so it does not speak for a person"))
	}
	if who == "" || raw == "" || rawSalt == "" {
		return refuse(fmt.Errorf("an app speaks for a person with their own signed statement of what they said: %s, %s and %s are all needed",
			headerSpeakingFor, headerPersonStatement, headerPersonSalt))
	}
	js, derr := base64.RawURLEncoding.Strict().DecodeString(raw)
	if derr != nil {
		return refuse(errors.New("the person's statement is not base64url"))
	}
	salt, derr = base64.RawURLEncoding.Strict().DecodeString(rawSalt)
	if derr != nil {
		return refuse(errors.New("the person's salt is not base64url"))
	}
	var proof agentmessage.PersonProof
	if json.Unmarshal(js, &proof) != nil {
		return refuse(errors.New("the person's statement is unreadable"))
	}
	st := proof.Statement
	if st.From != who {
		return refuse(errors.New("the statement is from somebody else than the person the app names"))
	}

	// What the statement says is what the request is: the words under the salt,
	// and the conversation, kind, recipient, reply and message id of this route
	// and body. A statement signed for other words, or for another thing, is
	// not this request's.
	words, msg, werr := theWordsAPersonSays(r, body)
	if werr != nil {
		return refuse(werr)
	}
	if st.Kind != agentmessage.PersonKindMessage && st.Kind != agentmessage.PersonKindAsk {
		return refuse(fmt.Errorf("a statement of kind %q is not what this route takes: it takes a message or an ask", st.Kind))
	}
	// The conversation is compared when the request names none too: a statement
	// is always for one conversation (its id is the person's to choose), so a
	// request that names none, which opens a new one, is not what any statement
	// said. The statement a person signed for c1 cannot open another.
	if st.Conversation != msg.Conversation {
		return refuse(errors.New("the statement is for another conversation than the request's, " +
			"and a request that opens one names the conversation the person signed for"))
	}
	// The AI agent is the one on the route the app called: a statement to agent
	// A is not delivered on agent B's route, whatever the body says.
	agent, isAgent := s.theAIAgentARouteNames(strings.Split(strings.Trim(r.URL.Path, "/"), "/")[3])
	if !isAgent {
		return refuse(errors.New("the route does not name an AI agent of this Identity Agent that has an identifier its entries are addressed to"))
	}
	if st.To != agent {
		return refuse(errors.New("the statement is to another AI agent than the one the request is sent to"))
	}
	if st.To != msg.To || st.InReplyTo != msg.InReplyTo {
		return refuse(errors.New("the statement is to someone else than the request's, or answers something else"))
	}
	if st.MessageID != msg.Nonce {
		return refuse(errors.New("the statement is for another message than the request's"))
	}

	// Then the statement is the person's: well formed, the key's signature, this
	// Identity Agent, a key the person's own sign-in at the app's asset named,
	// signed just now. Judged by the trail's one check.
	if verr := trail.CheckAuthor(trail.Write{Statement: st, Verkey: proof.Verkey, Signature: proof.Signature},
		s.thisIdentityAgentsIdentifier(), keysSpeakingAt{s: s, asset: grant.AppAsset}); verr != nil {
		return refuse(fmt.Errorf("the person's statement does not hold: %w", verr))
	}
	if ferr := trail.CheckFresh(st, time.Now()); ferr != nil {
		return refuse(fmt.Errorf("the person's statement does not hold: %w", ferr))
	}
	if cerr := agentmessage.CheckFingerprint(st.FingerprintVersion, salt, words, st.Fingerprint, false); cerr != nil {
		return refuse(fmt.Errorf("the statement is for other words than the request's: %w", cerr))
	}
	if used, uerr := s.rememberPersonStatement(proof.Signature, time.Now().UTC()); uerr != nil {
		return refuse(uerr)
	} else if used {
		return refuse(errors.New("this statement was already used"))
	}
	return coretypes.Signer{AID: who, Standing: "member", Asset: grant.AppAsset}, js, salt, true, nil
}

// theAIAgentARouteNames is the identifier a statement names an AI agent by, for
// the AI agent a route names, and whether the route names one. A route names it
// by its asset id, and the record, the statement and the verifier name it by the
// identifier its entries are addressed to (the asset's pairwise_aid), never the
// asset id. So it names none, and the request is refused, when no asset has that
// id, when the asset is not an AI agent, when it has no identifier yet, and when
// the asset cannot be read.
func (s *CoreServer) theAIAgentARouteNames(id string) (string, bool) {
	if s.assetHandler == nil {
		return "", false
	}
	a, found, err := s.assetHandler.Store.GetAsset(id)
	if err != nil || !found || a.AssetType != "ai_agent" || a.PairwiseAID == "" {
		return "", false
	}
	return a.PairwiseAID, true
}
