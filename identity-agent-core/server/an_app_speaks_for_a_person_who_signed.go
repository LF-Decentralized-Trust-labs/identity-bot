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
)

// An app's back end speaks for a person it serves (browser -> app -> core,
// ADR-006, ADR-066).
//
// A browser never reaches this core. The person's browser talks to the app, and
// the app's back end, an enrolled machine, talks to the core with the request
// it signs as any controller's (a_request_from_a_controller.go). To speak FOR a
// person it adds two things, both in headers so the signed body stays the
// words alone:
//
//	X-IA-Speaking-For      the person, by the identifier the organisation knows them by
//	X-IA-Person-Statement  that person's own signed statement over a salted
//	                       fingerprint of the words (ADR-067): base64url of
//	                       the JSON agentmessage.PersonProof
//
// The app's signature says the app asked. The person's says the person spoke.
// Both are needed, so an app cannot put words in a person's mouth: it holds no
// key of theirs, and a statement it made itself is signed by a key the person
// does not name. A person the app is not bound to is refused, whatever it
// carries.
const (
	headerSpeakingFor     = "X-IA-Speaking-For"
	headerPersonStatement = "X-IA-Person-Statement"
)

// ThePersonStatementThatSpoke is the person's own signed statement a request
// carried, as sent, when the request was an app speaking for a person.
func ThePersonStatementThatSpoke(proof *coretypes.ControllerProof) (agentmessage.PersonProof, bool) {
	if proof == nil || len(proof.PersonStatement) == 0 {
		return agentmessage.PersonProof{}, false
	}
	var p agentmessage.PersonProof
	if json.Unmarshal(proof.PersonStatement, &p) != nil {
		return agentmessage.PersonProof{}, false
	}
	return p, true
}

// thePersonAnAppSpeaksFor settles who the app speaks for. It reports false,
// with no error, when the request names no one: then the machine speaks as the
// signer it belongs to, as it always has. Once it names someone it is judged
// here, and refused unless every check holds.
func (s *CoreServer) thePersonAnAppSpeaksFor(r *http.Request, bound coretypes.Signer) (named coretypes.Signer, statement []byte, speaking bool, err error) {
	who := strings.TrimSpace(r.Header.Get(headerSpeakingFor))
	raw := strings.TrimSpace(r.Header.Get(headerPersonStatement))
	if who == "" && raw == "" {
		return coretypes.Signer{}, nil, false, nil
	}
	if who == "" {
		return coretypes.Signer{}, nil, true, errors.New("a person's statement names who it speaks for in " + headerSpeakingFor)
	}
	if raw == "" {
		return coretypes.Signer{}, nil, true, fmt.Errorf("this app may not speak for %s without their own signed statement of what they said", who)
	}
	// The person the app may serve is the one it is bound to. Anyone else is
	// refused before their statement is looked at.
	if bound.AID != who {
		return coretypes.Signer{}, nil, true, fmt.Errorf("this app does not serve %s", who)
	}
	if !s.personStillStands(bound) {
		return coretypes.Signer{}, nil, true, fmt.Errorf("%s is no longer someone this organisation can prove", who)
	}
	js, derr := base64.RawURLEncoding.Strict().DecodeString(raw)
	if derr != nil {
		return coretypes.Signer{}, nil, true, errors.New("the person's statement is not base64url")
	}
	var proof agentmessage.PersonProof
	if json.Unmarshal(js, &proof) != nil {
		return coretypes.Signer{}, nil, true, errors.New("the person's statement is unreadable")
	}
	if verr := proof.Verify(); verr != nil {
		return coretypes.Signer{}, nil, true, fmt.Errorf("the person's statement does not hold: %w", verr)
	}
	st := proof.Statement
	if st.From != who {
		return coretypes.Signer{}, nil, true, errors.New("the statement is from somebody else than the person the app names")
	}
	if me := s.thisIdentityAgentsIdentifier(); me == "" || st.Agent != me {
		return coretypes.Signer{}, nil, true, errors.New("the statement was signed for another Identity Agent")
	}
	at, _ := time.Parse(time.RFC3339, st.Time) // Check made sure it parses
	now := time.Now().UTC()
	if now.Sub(at) > signedRequestWindow || at.Sub(now) > signedRequestWindow {
		return coretypes.Signer{}, nil, true, fmt.Errorf("the statement was signed outside the %s window", signedRequestWindow)
	}
	if rememberSignature("person:"+proof.Signature, now) {
		return coretypes.Signer{}, nil, true, errors.New("this statement was already used")
	}
	return bound, js, true, nil
}
