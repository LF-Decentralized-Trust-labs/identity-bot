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
// repositories, over its body's own signed channel (ADR-045, Amendment 3). The
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
// this AI agent, by that name, with those capabilities and limits. It also
// vouches that the AI agent created is no more powerful than its creator: it
// holds only capabilities the creator's grant holds, and where the creator's
// grant limits the values of an argument, its own limit is within that, and
// where the creator's grant lapses, its own lapses no later. What it
// does not vouch for is any count or resource limit on how many AI agents the
// creator may create, or how much they may use: the core does not enforce
// those, and the party that issues the creator's grant does (ADR-045,
// Amendment 3).

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

	if err := withinCreator(grant.A, cred.A); err != nil {
		return err
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

// withinCreator checks that what a created AI agent's grant gives is within
// what its creator's grant gives: every capability is one the creator holds,
// and for every argument the creator's grant limits to some values, the created
// grant limits it to some of those. A limit the creator has and the created
// grant leaves off is wider, and refused. So is a grant that lasts longer: where
// the creator's grant lapses, the created grant must lapse too, no later, or the
// AI agent would outlive its creator. A list of values that is empty is refused
// in either grant, as the schema refuses it.
func withinCreator(creator, created map[string]json.RawMessage) error {
	var held, given []string
	if err := json.Unmarshal(creator["capabilities"], &held); err != nil {
		return fmt.Errorf("the creator's capabilities are unreadable")
	}
	if err := json.Unmarshal(created["capabilities"], &given); err != nil {
		return fmt.Errorf("the capabilities of the AI agent created are unreadable")
	}
	holds := map[string]bool{}
	for _, c := range held {
		holds[c] = true
	}
	for _, c := range given {
		if !holds[c] {
			return fmt.Errorf("the AI agent created would hold %s, which its creator's grant does not", c)
		}
	}
	if _, ok := creator["valid_until"]; ok {
		ends, err := timeAttr(creator, "valid_until")
		if err != nil {
			return fmt.Errorf("the creator's grant says when it lapses unreadably")
		}
		if _, ok := created["valid_until"]; !ok {
			return fmt.Errorf("the AI agent created has no end, but its creator's grant lapses at %s", ends.Format(time.RFC3339))
		}
		own, err := timeAttr(created, "valid_until")
		if err != nil {
			return fmt.Errorf("the AI agent created says when it lapses unreadably")
		}
		if own.After(ends) {
			return fmt.Errorf("the AI agent created lapses at %s, after its creator's grant lapses at %s", own.Format(time.RFC3339), ends.Format(time.RFC3339))
		}
	}
	type limits map[string]map[string][]string
	var creatorLimits, createdLimits limits
	if raw := creator["resource_constraints"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &creatorLimits); err != nil {
			return fmt.Errorf("the creator's limits are unreadable")
		}
	}
	if raw := created["resource_constraints"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &createdLimits); err != nil {
			return fmt.Errorf("the limits of the AI agent created are unreadable")
		}
	}
	for who, all := range map[string]limits{"creator's grant": creatorLimits, "AI agent created": createdLimits} {
		for c, args := range all {
			for arg, values := range args {
				if len(values) == 0 {
					return fmt.Errorf("the %s lists no values for %s of %s: a limit names at least one", who, arg, c)
				}
			}
		}
	}
	for _, c := range given {
		for arg, allowed := range creatorLimits[c] {
			own, ok := createdLimits[c][arg]
			if !ok {
				return fmt.Errorf("the AI agent created has no limit on %s of %s, which its creator's grant limits", arg, c)
			}
			set := map[string]bool{}
			for _, v := range allowed {
				set[v] = true
			}
			for _, v := range own {
				if !set[v] {
					return fmt.Errorf("the AI agent created may use %q for %s of %s, which its creator's grant does not allow", v, arg, c)
				}
			}
		}
	}
	return nil
}
