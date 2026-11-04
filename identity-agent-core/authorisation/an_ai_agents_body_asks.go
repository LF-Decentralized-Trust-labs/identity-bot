package authorisation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

// A request an AI agent's body made.
//
// An AI agent whose grant holds agent.create creates AI agents, and sets their
// repositories, over its body's own signed channel (ADR-061 of the add-ons). The
// grant issued for the AI agent it created rests on that request: the request
// kind is "ai_agent_body", and its signer is the machine, the body, that signed
// it. What the grant's authority then names is two credentials and a string:
//
//   - the creator's AI Agent Grant, the credential its authorised_by edge
//     names, which must hold agent.create and have been in force when the
//     request was made;
//   - the creator's body credential, the one that says the signing machine's
//     key speaks as the creator, in force at the same time;
//   - the string the body signed, in the form agentbody.SignedRequest.Bytes
//     writes, which names the Identity Agent it was for, the body, the method
//     and target, the time, and the digest of the request's body.
//
// What it vouches for is the same as for any request: that the creator asked for
// this AI agent, by that name, with those capabilities and limits. What it does
// not vouch for is that those are within the creator's own: that a created AI
// agent is never wider than its creator is the creating Identity Agent's rule
// and shows in the two grants, not in this check.

// KindAIAgentBody is the kind of a request an AI agent's body signed.
const KindAIAgentBody = "ai_agent_body"

// The routes a body signs a request to that grant something to an AI agent.
const (
	// CreateAIAgentPath is where a body asks for an AI agent to be created.
	CreateAIAgentPath = "/api/agent-host/agents"
)

// capabilityCreate is the capability that lets an AI agent create AI agents.
const capabilityCreate = "agent.create"

// BodyRequest is what a body's signed request string says.
type BodyRequest struct {
	// IdentityAgent is the Identity Agent the request was for.
	IdentityAgent string
	// Host is the body that signed it.
	Host                  string
	Method, Target, Stamp string
	// BodyDigest is the digest of the request's body.
	BodyDigest string
}

// ReadBodyRequest reads the string a body signed for a request: the one
// reading of it, whose form agentbody.SignedRequest.Bytes writes.
func ReadBodyRequest(signed string) (BodyRequest, error) {
	lines := strings.Split(signed, "\n")
	if len(lines) != 11 || lines[0] != "IA-BODY-REQ-V3" {
		return BodyRequest{}, fmt.Errorf("the signed string is not an AI agent body's request")
	}
	return BodyRequest{IdentityAgent: lines[1], Host: lines[2], Method: lines[3], Target: lines[4], Stamp: lines[5], BodyDigest: lines[7]}, nil
}

// checkCreator checks a body's request against the creator's grant and the
// creator's body credential.
func checkCreator(in Input, cred acdc, rests RestsOn, req request, br BodyRequest, issuedAt time.Time) error {
	if cred.Schema != schemas.AIAgentGrant.Schema.SAID {
		return fmt.Errorf("a request an AI agent's body made authorises only a grant of the version that admits it")
	}
	if rests.Grant == "" && rests.GrantSchema == "" {
		return fmt.Errorf("an AI agent body's request with no edge to its creator's grant")
	}
	switch rests.GrantSchema {
	case schemas.AIAgentGrant.Schema.SAID, schemas.AIAgentGrantV11.Schema.SAID, schemas.AIAgentGrantV1.Schema.SAID:
	default:
		return fmt.Errorf("the edge names a credential that is not an AI Agent Grant")
	}
	g, err := keri.VerifyCredential(in.Grant)
	if err != nil {
		return fmt.Errorf("the creator's grant does not verify: %w", err)
	}
	if g.SAID != rests.Grant {
		return fmt.Errorf("the grant given is %s, not the %s the edge names", g.SAID, rests.Grant)
	}
	var grant acdc
	if err := json.Unmarshal(in.Grant, &grant); err != nil {
		return err
	}
	if grant.Schema != rests.GrantSchema {
		return fmt.Errorf("the grant given is not of the schema the edge names")
	}
	if grant.Issuer != cred.Issuer {
		return fmt.Errorf("the creator's grant was issued by %s, the credential by %s", grant.Issuer, cred.Issuer)
	}
	creator := stringAttr(grant.A, "i")
	if creator == "" || creator == stringAttr(cred.A, "i") {
		return fmt.Errorf("an AI agent's grant does not rest on its own request")
	}
	var caps []string
	if err := json.Unmarshal(grant.A["capabilities"], &caps); err != nil {
		return fmt.Errorf("the creator's capabilities are unreadable")
	}
	holds := false
	for _, c := range caps {
		holds = holds || c == capabilityCreate
	}
	if !holds {
		return fmt.Errorf("the creator's grant does not hold %s", capabilityCreate)
	}

	b, err := keri.VerifyCredential(in.CreatorBody)
	if err != nil {
		return fmt.Errorf("the creator's body credential does not verify: %w", err)
	}
	var body acdc
	if err := json.Unmarshal(in.CreatorBody, &body); err != nil {
		return err
	}
	if body.Schema != schemas.AIAgentBody.Schema.SAID && body.Schema != schemas.AIAgentBodyV1.Schema.SAID {
		return fmt.Errorf("the body credential given is not an AI agent's body")
	}
	if body.Issuer != cred.Issuer {
		return fmt.Errorf("the creator's body was approved by %s, the credential issued by %s", body.Issuer, cred.Issuer)
	}
	if stringAttr(body.A, "i") != creator {
		return fmt.Errorf("the body credential is for %s, the grant is %s's", stringAttr(body.A, "i"), creator)
	}
	host, verkey := stringAttr(body.A, "host"), stringAttr(body.A, "verkey")
	if host != req.Signer || host != br.Host {
		return fmt.Errorf("the request was signed by %s, but the creator's body is %s", req.Signer, host)
	}
	if err := agentbody.Verify(host, verkey, req.Signature, []byte(req.Signed)); err != nil {
		return fmt.Errorf("the request is not signed by the creator's body: %w", err)
	}
	if err := checkStanding(in, cred, standing{what: "the creator's grant", said: g.SAID, attrs: grant.A, log: in.GrantLog}, br.Stamp, issuedAt); err != nil {
		return err
	}
	return checkStanding(in, cred, standing{what: "the creator's body credential", said: b.SAID, attrs: body.A, log: in.CreatorBodyLog}, br.Stamp, issuedAt)
}
