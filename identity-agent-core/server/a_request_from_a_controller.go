package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/endpointrecord"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// Recognising a request from a machine this identity authorised.
//
// The shape is the owner-signature path with one substitution: the key a
// signature is checked against comes from the grant rather than from the owner
// authority. Everything that makes that path safe is kept — the request is
// signed over its own method, path and body, the timestamp bounds the window,
// and a signature is spent once so a captured one cannot be replayed.
//
// WHAT IT NEVER DOES IS SIGN AS THE IDENTITY. A controller signs as ITSELF, with
// the key that never left it, and asks the agent to act. The agent performs its
// own key operations, always. That is why revoking a grant is enough to stop a
// machine: it never held anything of the identity's to keep.

const (
	headerControllerAID       = "X-IA-Controller-AID"
	headerControllerSig       = "X-IA-Controller-Sig"
	headerControllerTimestamp = "X-IA-Controller-Timestamp"
	// headerControllerFor names the Identity Agent the request is meant for, by
	// its identifier. It is inside the signature, and an Identity Agent refuses
	// a request that names anybody but itself — see theIdentityAgentItNames.
	headerControllerFor = "X-IA-Controller-For"
	// headerControllerOrigin names the origin (scheme://host:port) the machine
	// meant to reach. It is inside the signature, and an Identity Agent refuses
	// a request that names an origin that is not one of its own — see
	// theOriginItNames.
	headerControllerOrigin = "X-IA-Controller-Origin"

	// How well the person was authenticated, and who says so.
	//
	// The controller CARRIES these; it does not get to make them up. The level is
	// established on the device holding this identity's root key, which signs the
	// statement, and headerAuthLevelVouchedBy is that signature. Without it the
	// level counts as nothing measured — see theAuthenticationSomebodyVouchedFor
	// for why a machine may not score itself.
	//
	// The first three are bound into the request signature, so nothing in the
	// middle can alter them in flight. The vouching signature is not: stripping
	// it downgrades the level to nothing measured, which then disagrees with the
	// level inside the signed string, and the request is refused as a mismatch.
	// The outcome is the same and the mechanism is not, which is worth saying
	// rather than leaving a reader to assume all four are covered the same way.
	//
	// Either way this is defence in depth, not the thing that makes
	// them trustworthy.
	headerControllerAuthLevel = "X-IA-Controller-Auth-Level"
	headerControllerAuthAt    = "X-IA-Controller-Auth-At"
	headerControllerAuthScore = "X-IA-Controller-Auth-Score"
	headerAuthLevelVouchedBy  = "X-IA-Auth-Level-Vouched-By"
)

// canonicalAuthLevelStatement is what the device holding the root key signs when
// it says how well somebody was authenticated.
//
// Bound to ONE controller, so a statement made for the laptop cannot be relayed
// by a different machine. Bound to the moment, so freshness means something. Its
// own first line so it can never be confused with a request signature.
//
// It is not bound to a single request, and that is a real choice: the person
// authenticates on their phone and then works at the laptop, so the statement
// covers a short window rather than one action. What that costs is that a
// controller compromised DURING the window can spend it on something other than
// what the person had in mind — which is the argument for binding the highest
// actions to a specific one, and is left open deliberately.
func canonicalAuthLevelStatement(
	controllerAID string, level authprovider.Level, at time.Time, score int,
) string {
	return strings.Join([]string{
		"IA-AUTH-LEVEL-V1",
		controllerAID,
		string(level),
		at.UTC().Format(time.RFC3339),
		strconv.Itoa(score),
	}, "\n")
}

// controllerContextKey carries which machine acted, for anything downstream that
// needs to record it.
//
// An action taken from an authorised laptop and one taken by the owner at their
// own device are not the same event, and an audit trail that cannot tell them
// apart cannot answer the question somebody asks after a machine is stolen:
// what did it do. Its own type so nothing else can collide with it.
type controllerContextKey struct{}

// TheControllerThatAsked names the machine that signed this request, if one did.
//
// Empty for the owner acting directly, which is the honest answer rather than a
// default — nothing acted for them.
func TheControllerThatAsked(r *http.Request) (ControllerGrant, bool) {
	g, ok := r.Context().Value(controllerContextKey{}).(ControllerGrant)
	return g, ok
}

// controllerActsForTheOwner serves this request if an authorised machine signed
// it and the action is within what the person at that machine has proved.
//
// Reports whether it answered — either by serving or by refusing. False means
// no machine signed this, and the caller should carry on trying whatever else
// might stand in for the owner.
//
// A machine the owner authorised acts for them on everything except the
// owner-only list, and every action it may do passes the one check shared with
// AI agents' capability calls: the person's identity score against the action's
// minimum, then whether they may do it (what_a_controller_may_reach.go).
func (s *CoreServer) controllerActsForTheOwner(
	w http.ResponseWriter, r *http.Request, pattern string, next http.Handler,
) bool {
	grant, _, err := s.theControllerBehindIf(r, func(grant ControllerGrant, vouched authprovider.Result) error {
		// Before the body is read: whether this machine may use this route at
		// all depends on the route and the headers, never on the body, so a
		// route it may not use costs the agent no read.
		authenticated := howSureWeAreItIsThem(vouched, time.Now().UTC())
		if ok, why := mayThisControllerDoThis(
			r.Method, pattern, grant.ControllerAID, authenticated); !ok {
			return aControllerRefusedHere{
				code:    whyAControllerWasRefused(r.Method, pattern, authenticated),
				message: "this machine may act for you, but " + why,
			}
		}
		return nil
	})
	if err != nil {
		var refused aControllerRefusedHere
		if errors.As(err, &refused) {
			denyAuthorizationBecause(w, refused.code, refused.message)
			return true
		}
		// A body is not a signature: say so, as the owner path does.
		if refuseTheBody(w, err) {
			return true
		}
		// A request carrying no controller headers at all is simply not from a
		// controller, and the caller carries on trying whatever else might stand
		// in for the owner. Anything else IS a controller and was refused for a
		// reason the person needs, so say it here rather than letting them fall
		// through to "sign the request with the owner key" — advice a controller
		// cannot act on, since by design it has no owner key.
		//
		// It also mattered for faults: an unreadable grants file gave every
		// authorised machine the same misleading line, with nothing reporting
		// that anything was wrong.
		if errors.Is(err, errNotFromAController) {
			return false
		}
		denyAuthorization(w, err.Error())
		return true
	}
	// Carried forward so what this machine did is attributable to it rather than
	// to the owner.
	next.ServeHTTP(w, r.WithContext(
		context.WithValue(r.Context(), controllerContextKey{}, grant)))
	return true
}

// aControllerRefusedHere is the refusal for a machine whose grant stands but
// which may not do this action, raised before the body is read.
type aControllerRefusedHere struct{ code, message string }

func (e aControllerRefusedHere) Error() string { return e.message }

// errNotFromAController means no machine claimed this request, which is the
// ordinary case for every other caller and not a fault.
//
// Distinct from the other refusals because it is the only one where the right
// thing to do is carry on and try something else. The rest describe a machine
// that IS a controller and could not be admitted, and each of those needs
// different action from the person.
var errNotFromAController = errors.New("this request is not from a controller")

// theControllerBehind identifies the machine that signed this request, if a
// machine did and its grant still stands.
//
// The error says which of those failed, because "not a controller" and "your
// authorisation ran out" need different things from the person.
func (s *CoreServer) theControllerBehind(r *http.Request) (ControllerGrant, authprovider.Result, error) {
	return s.theControllerBehindIf(r, nil)
}

// theControllerBehindIf is theControllerBehind with a check run once the grant
// is known to stand and before the body is read. An error from it refuses the
// request as it stands, so a request that is refused for what it asks for is
// never made to cost a read of what it carries. Nil checks nothing.
func (s *CoreServer) theControllerBehindIf(
	r *http.Request, beforeTheBody func(ControllerGrant, authprovider.Result) error,
) (ControllerGrant, authprovider.Result, error) {
	var none ControllerGrant
	unmeasured := authprovider.Unmeasured("this machine reported no authentication")

	aid := strings.TrimSpace(r.Header.Get(headerControllerAID))
	sig := strings.TrimSpace(r.Header.Get(headerControllerSig))
	stamp := strings.TrimSpace(r.Header.Get(headerControllerTimestamp))
	if aid == "" || sig == "" {
		return none, unmeasured, errNotFromAController
	}
	if stamp == "" {
		return none, unmeasured, fmt.Errorf(
			"a signed request must carry %s", headerControllerTimestamp)
	}
	signedAt, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return none, unmeasured, fmt.Errorf("%s must be RFC3339", headerControllerTimestamp)
	}
	now := time.Now().UTC()
	if diff := now.Sub(signedAt); diff > signedRequestWindow || diff < -signedRequestWindow {
		return none, unmeasured, fmt.Errorf(
			"this request was signed outside the %s window", signedRequestWindow)
	}

	// The grant decides whether this machine is anybody, and is checked before
	// the signature only to fail fast.
	//
	// Admitting still requires the signature to verify against the key the GRANT
	// records, below — reaching this point proves nothing. What the refusal is
	// allowed to SAY, though, does depend on proof, and that is settled
	// separately: an unproven caller gets the same sentence it always got, and
	// only a caller that demonstrates it holds this machine's key learns which
	// of the reasons applies.
	grant, live, err := s.controllers().Live(aid, now)
	if err != nil {
		return none, unmeasured, fmt.Errorf(
			"which machines may act for this identity could not be read, so none were admitted: %w", err)
	}
	if !live {
		// The refusal is the same either way; only what it SAYS depends on
		// whether the caller can prove it is the machine it claims to be. See
		// why_a_machine_was_not_admitted.go — nothing there can admit anybody.
		return none, unmeasured, s.whyThisMachineWasNotAdmitted(r, aid, sig, stamp, now)
	}

	// The key is NOT decoded here any more. A machine's key is P-256 where an
	// identity's is Ed25519, and the published form says which -- so the form is
	// carried to the verifier, which asks once, rather than being flattened to
	// raw bytes that no longer say what they are.
	if grant.PublicKey == "" {
		return none, unmeasured, fmt.Errorf("no key is recorded for this machine")
	}

	if beforeTheBody != nil {
		if err := beforeTheBody(grant, s.theAuthenticationSomebodyVouchedFor(r, aid, now)); err != nil {
			return none, unmeasured, err
		}
	}

	signed, asserted, err := s.theStringThisMachineSigned(r, aid, stamp, now)
	if err != nil {
		return none, unmeasured, err
	}
	ok, err := iacrypto.VerifyMachineSignature(grant.PublicKey, sig, []byte(signed))
	if err != nil {
		return none, unmeasured, fmt.Errorf("signature: %w", err)
	}
	if !ok {
		// Also what a tampered authentication level lands on, since the level is
		// inside the signed string.
		return none, unmeasured, fmt.Errorf(
			"this request was not signed by the machine it claims to be from")
	}

	// Verified, so spent NOW -- before any of the body is read, for the reasons
	// given where the owner path does the same: a mismatched body burns the
	// signature, so a captured request cannot be resent to make the agent read
	// again, and parallel resends cannot all be read before the first spends it.
	// Checked after the signature verifies so a bad signature cannot burn a good
	// one by presenting it first.
	if rememberSignature(sig, now) {
		return none, unmeasured, fmt.Errorf("this signed request has already been used")
	}

	// Signed by the machine, so a declared body is read now and must be the one
	// signed.
	if err := theBodyAMachineSigned(r); err != nil {
		return none, unmeasured, err
	}
	return grant, asserted, nil
}

// theStringThisMachineSigned builds (reading the body, and putting it back, only for a request without X-IA-Body-Digest)
// the exact string a controller's signature covers.
//
// ONE PLACE KNOWS WHAT A CONTROLLER SIGNS. Two paths need it — admitting a
// machine, and deciding how much a refusal is allowed to say — and the only
// thing that legitimately differs between them is which key they check against.
// Everything up to that point is the same steps in the same order, and written
// twice it drifts: a field added to the canonical string, or a change to the
// size limit, applied to one copy leaves the refusal path verifying a different
// string from the admitting one. The symptom would be a machine that is admitted
// normally and given the wrong explanation when it is not — a wrong error
// message, which is close to the last thing anybody investigates.
//
// A body over the limit is REFUSED, never truncated. Truncating would hand the
// handler a shortened body and check the signature against that same shortened
// copy, so the two would agree and the request would succeed while silently
// doing something other than what was sent — a transfer, a policy, a list, cut
// off at the limit with nothing reporting it.
//
// PUT IT BACK ON EVERY PATH, INCLUDING THE REFUSALS. A refusal is not the end of
// the request: the caller turns it into "no controller signed this", and the
// middleware carries on to whatever else might stand in for the owner. If the
// body were left consumed, that next handler would serve a silently truncated
// request — the same failure this reads carefully to avoid, moved one layer out.
// Measured before the fix: 12,582,976 bytes sent, 63 still readable afterwards.
func (s *CoreServer) theStringThisMachineSigned(
	r *http.Request, aid, stamp string, now time.Time,
) (string, authprovider.Result, error) {
	// With X-IA-Body-Digest the string is built from the digest the machine
	// declared and no body is read here at all; theBodyAMachineSigned reads and
	// matches it once the signature has verified. Without it (an older client)
	// the body is read, at maxSignedBodyBytes only, and digested. The header
	// becomes required in a later version.
	digest, declared, err := theDigestTheRequestDeclares(r)
	if err != nil {
		return "", authprovider.Result{}, err
	}
	if !declared {
		body, err := readSignedBody(r)
		if err != nil {
			return "", authprovider.Result{}, err
		}
		digest = iacrypto.Blake3QB64Must(body)
	}
	target, err := s.theIdentityAgentItNames(r)
	if err != nil {
		return "", authprovider.Result{}, err
	}
	origin, err := s.theOriginItNames(r)
	if err != nil {
		return "", authprovider.Result{}, err
	}

	asserted := s.theAuthenticationSomebodyVouchedFor(r, aid, now)
	// The signature covers the level as the machine sent it; what is acted on
	// carries the level derived from the score.
	signedAs := asserted
	if asserted.Measured {
		signedAs.Level = authprovider.Level(strings.TrimSpace(r.Header.Get(headerControllerAuthLevel)))
	}
	return canonicalControllerRequestOver(
		aid, target, origin, r.Method, r.URL.Path, stamp, signedAs, digest), asserted, nil
}

// theBodyAMachineSigned reads the body of a request whose signature has
// verified and which declared its digest (X-IA-Body-Digest), bounded by the
// route and refused unless it is the body that was signed. Nothing to do for a
// request without the header: its body was read, at the default bound, to build
// the string that verified.
func theBodyAMachineSigned(r *http.Request) error {
	digest, declared, err := theDigestTheRequestDeclares(r)
	if err != nil || !declared {
		return err
	}
	return readTheBodyAgainst(r, digest)
}

// theIdentityAgentItNames is the Identity Agent a controller's request is meant
// for, refused unless it is this one.
//
// A REQUEST IS SIGNED FOR ONE IDENTITY AGENT. Without that, a request captured
// on its way to one Identity Agent could be presented, within the window, to a
// second that also holds a grant for the same machine: each keeps its own
// memory of spent signatures, so neither would know it had been used. Naming
// the target inside the signature makes the copy worthless anywhere else.
//
// One request is allowed to name nobody: a machine asking which identity it
// acts for, which is how it learns the identifier it will name from then on.
// That request changes nothing and answers the machine only with what its own
// grant there says, so a copy presented elsewhere tells the presenter what that
// other Identity Agent would tell the machine itself.
//
// An Identity Agent that has no identifier yet is named by nobody, so it
// accepts only a request that names nobody — and refuses those the moment it
// has one, which is what makes them worthless at a named Identity Agent.
func (s *CoreServer) theIdentityAgentItNames(r *http.Request) (string, error) {
	named := strings.TrimSpace(r.Header.Get(headerControllerFor))
	me, err := s.whoThisIdentityAgentIs()
	if err != nil {
		return "", err
	}
	switch {
	case named == me:
		return named, nil
	case named == "" && r.Method == http.MethodGet && r.URL.Path == controllerLearnsWhoItActsFor:
		return "", nil
	case named == "":
		return "", fmt.Errorf(
			"a signed request must name the Identity Agent it is for in %s", headerControllerFor)
	default:
		return "", fmt.Errorf("this request was signed for a different Identity Agent")
	}
}

// requireControllerOrigin reports whether X-IA-Controller-Origin is mandatory,
// set by REQUIRE_CONTROLLER_ORIGIN=1 (or true). It is OFF by default, which is
// the grace: a client built before the origin was signed sends no such header
// and is read in the V2 form, so it keeps working. A client that does send the
// header can never be read as V2, because the two forms are different strings.
//
// WHEN IT FLIPS. The default turns to on in step (d) of the rollout in ADR-062,
// the release after the apps start sending the origin, and the no-header path
// is removed with it; until then an operator can switch it on as soon as every
// app that reaches the agent sends the origin. Read at each request, so a test
// or an operator's restart is all it takes.
func requireControllerOrigin() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("REQUIRE_CONTROLLER_ORIGIN")))
	return v == "1" || v == "true"
}

// theOriginItNames is the origin a controller's request is meant for, refused
// unless it is one of this Identity Agent's own.
//
// A REQUEST IS SIGNED FOR ONE ADDRESS. Naming the Identity Agent in the
// signature already makes a copy worthless at a different Identity Agent, but
// not at a different address of the same one — and a plain reverse proxy is
// exactly that: a host the client was led to, which relays what it is sent and
// what comes back. A request signed for the proxy's origin is refused here,
// because the proxy's origin is not one of ours.
//
// The origin is the client's own statement of where it meant to go, so it is
// checked against what this agent knows about itself (its relay, tunnel, public
// URL, direct address and loopback), never against the Host header, which the
// forwarder chooses.
//
// No header is the older form, accepted for one version (requireControllerOrigin).
// A header that is present but not one origin in its one spelling is an error,
// never "absent": treating it as no header would let the sender pick the older
// form.
func (s *CoreServer) theOriginItNames(r *http.Request) (string, error) {
	values := r.Header.Values(headerControllerOrigin)
	if len(values) == 0 {
		if requireControllerOrigin() {
			return "", fmt.Errorf("a signed request must name the origin it is for in %s", headerControllerOrigin)
		}
		return "", nil
	}
	if len(values) > 1 {
		return "", fmt.Errorf("%s must be sent once", headerControllerOrigin)
	}
	origin := values[0]
	if origin == "" {
		return "", fmt.Errorf("%s is empty", headerControllerOrigin)
	}
	if err := endpointrecord.CheckOrigin(origin); err != nil {
		return "", fmt.Errorf("%s: %w", headerControllerOrigin, err)
	}
	if !s.isOneOfThisAgentsOrigins(origin) {
		return "", fmt.Errorf("this request was signed for %s, which is not an address of this Identity Agent", origin)
	}
	return origin, nil
}

// isOneOfThisAgentsOrigins reports whether origin is an address this agent
// knows it is reached at.
func (s *CoreServer) isOneOfThisAgentsOrigins(origin string) bool {
	if s.EndpointService == nil {
		return false
	}
	for _, address := range s.EndpointService.OwnURLs() {
		if own, err := endpointrecord.OriginOf(address); err == nil && own == origin {
			return true
		}
	}
	return false
}

// controllerLearnsWhoItActsFor is the one route a controller may sign for
// without naming the Identity Agent, because it is how the controller learns
// the name.
const controllerLearnsWhoItActsFor = "/api/controller/agent"

// theAuthenticationSomebodyVouchedFor reads how well the person was
// authenticated, and accepts it only from somebody entitled to say.
//
// A MACHINE MAY NOT SCORE ITSELF. An authentication level is only worth what the
// software producing it can be held to: if the controller measures the person
// and reports the answer, then whoever runs modified software on that machine
// reports whatever they like, and every threshold in this package becomes a
// number the attacker chooses. Nobody is auditing what build is running there.
//
// So the level has to be established where the build can be attested. By default
// that is the device holding this identity's root key — in most cases a phone —
// and this agent already knows the key that device signs with. The controller
// RELAYS the statement; it does not make it. A machine that could attest its own
// build could make it too, but that is a decision about which devices qualify,
// and it is not this function's to take.
//
// Absence is Unmeasured rather than a low level, matching the provider seam: an
// agent that measured nothing must not be treated as one that measured and found
// little, or removing the provider would be a way past a gate.
func (s *CoreServer) theAuthenticationSomebodyVouchedFor(
	r *http.Request, controllerAID string, now time.Time,
) authprovider.Result {

	level := authprovider.Level(strings.TrimSpace(r.Header.Get(headerControllerAuthLevel)))
	at := strings.TrimSpace(r.Header.Get(headerControllerAuthAt))
	vouched := strings.TrimSpace(r.Header.Get(headerAuthLevelVouchedBy))
	if level == "" || at == "" {
		return authprovider.Unmeasured("nobody has said how well this person was authenticated")
	}
	when, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return authprovider.Unmeasured("when the person was checked was reported unreadably")
	}
	if !level.Known() {
		// A level this build does not define is not a level. Treated as nothing
		// measured, so a newer device inventing a name cannot clear a gate on an
		// older agent.
		return authprovider.Unmeasured(
			"an authentication level this agent does not recognise was reported")
	}
	score, _ := strconv.Atoi(strings.TrimSpace(r.Header.Get(headerControllerAuthScore)))

	// The statement has to be signed by the device that made it. Unsigned, this
	// is the controller scoring itself, which is worth nothing.
	if vouched == "" {
		return authprovider.Unmeasured(
			"this machine reported an authentication level with nothing vouching for it, " +
				"and a machine may not score itself")
	}
	// WHOSE KEY THIS IS CHECKED AGAINST MATTERS AS MUCH AS THE CHECK.
	//
	// Not ownerAuthority(), which is right for deciding whether a request came
	// from the owner and wrong here. Two of its answers are derived from state a
	// request can write — the agent's own identity record, and the contact the
	// owner's key is resolved from — so a caller who could reach either could
	// install the key that vouches for it and then vouch for itself at the
	// strongest level. That is not hypothetical: it was reachable on this branch
	// at no authentication level at all, because a controller is permitted by
	// default and neither route was named.
	//
	// Those routes are closed to controllers now. This is the second lock, and
	// it is the one that does not depend on having thought of every route.
	key, kerr := s.theKeyEntitledToVouch()
	if kerr != nil {
		return authprovider.Unmeasured(
			"this agent knows of no device entitled to say how well somebody was authenticated")
	}
	pub, err := login.DecodeVerkey(key)
	if err != nil {
		return authprovider.Unmeasured("the key of the device that vouches is unusable")
	}
	ok, err := login.VerifyString(
		canonicalAuthLevelStatement(controllerAID, level, when, score), vouched, pub)
	if err != nil || !ok {
		return authprovider.Unmeasured(
			"the authentication level was not vouched for by the device that holds this identity's key")
	}

	// The level shown is derived from the score, so the two cannot disagree;
	// the level named in the statement only had to be one this build defines.
	return authprovider.Result{
		Level:    authprovider.LevelForScore(score),
		Score:    score,
		Measured: true,
		At:       when.UTC(),
		Provider: "root-identity-device",
	}
}

// canonicalControllerRequest is the string a controller signs.
//
// Distinct from the owner's canonical string by its first line, so a signature
// made for one can never be presented as the other — the owner path and this one
// admit different keys to different authority, and a string both would accept is
// a way to cross between them.
//
// The asserted authentication is part of it. Left out, a level would be an
// unauthenticated header on an authenticated request, and anything in the middle
// could raise it.
//
// So is the Identity Agent it is meant for, so a copy is refused by every
// other one (theIdentityAgentItNames). Empty only on the request a machine
// makes to learn that identifier.
//
// So is the machine's own identifier. The signature is already checked against
// the key recorded for that identifier, so this is not what stops an imposter —
// it stops one machine's signature from being presented under another's name,
// and it keeps two machines from ever producing identical signed bytes for the
// same request, which the replay guard would otherwise treat as a reused one.
func canonicalControllerRequest(
	controllerAID, target, method, path, timestamp string,
	authenticated authprovider.Result,
	body []byte,
) string {
	return canonicalControllerRequestAt(controllerAID, target, "", method, path, timestamp, authenticated, body)
}

// canonicalControllerRequestOver is canonicalControllerRequest from the body's
// digest, so a request can be checked before its body is read. The one place the
// string is built.
func canonicalControllerRequestOver(
	controllerAID, target, origin, method, path, timestamp string,
	authenticated authprovider.Result,
	bodyDigest string,
) string {
	measuredAt := ""
	if authenticated.Measured && !authenticated.At.IsZero() {
		measuredAt = authenticated.At.UTC().Format(time.RFC3339)
	}
	level := ""
	if authenticated.Measured {
		level = string(authenticated.Level)
	}
	// The origin is a line of its own, and a request that names one is a
	// different form (V3), so the two can never be mistaken for each other:
	// stripping the origin from a signed request leaves a string it was not
	// signed over, and the signature fails. One list, with the origin put in,
	// so the forms cannot drift apart.
	form, named := "IA-CONTROLLER-REQ-V2", []string{controllerAID, target}
	if origin != "" {
		form, named = "IA-CONTROLLER-REQ-V3", append(named, origin)
	}
	lines := append([]string{form}, named...)
	lines = append(lines,
		strings.ToUpper(method),
		path,
		timestamp,
		level,
		measuredAt,
		strconv.Itoa(authenticated.Score),
		bodyDigest,
	)
	return strings.Join(lines, "\n")
}

// canonicalControllerRequestAt is canonicalControllerRequest for a request that
// names the origin it is meant for. An empty origin is the older form.
func canonicalControllerRequestAt(
	controllerAID, target, origin, method, path, timestamp string,
	authenticated authprovider.Result,
	body []byte,
) string {
	return canonicalControllerRequestOver(
		controllerAID, target, origin, method, path, timestamp, authenticated, iacrypto.Blake3QB64Must(body))
}

// theKeyEntitledToVouch is whose statement about an authentication level this
// agent will believe.
//
// Deliberately narrower than ownerAuthority, which also answers from an
// unverified contact row — a row written by handlers that fetch a record from an
// address the caller names. Believing that here would let anything able to reach
// one of those routes install the key that vouches for it and then vouch for
// itself at the strongest level. That was reachable, and it was reachable again
// through a second route after the first was closed, which is why this does not
// depend on the list of routes being complete.
//
// Two sources, both of which a request cannot write:
//
//   - the record sealed at provisioning or at pairing, written before this agent
//     was reachable and now written only once;
//   - the owner's current key as this agent verified it against a key event log,
//     which is evidence rather than an assertion.
//
// Neither present means nobody may speak for this identity: no statement is
// believed, and every controller is judged on the placeholder score alone. That
// is a real configuration rather than a test shape — an identity founded
// through inception names an owner but seals no key for them, because inception
// is given the owner's identifier and not their key — so on that agent no
// controller can be vouched above the placeholder until the owner's log has
// been verified. That is the right answer while nothing trustworthy says
// otherwise; the way to change it is to verify the owner's log, not to lower
// this.
func (s *CoreServer) theKeyEntitledToVouch() (string, error) {
	// THE LOG DECIDES WHO, AND THE SEALED RECORD ONLY SUPPLIES A KEY FOR THAT
	// SOMEBODY. Exactly as ownerAuthority does it, and for the same reason.
	//
	// This used to return the sealed key without asking who the log named. That
	// split the two questions apart: a sealed record naming an identity the
	// inception never anchored was REFUSED for "who is the owner" and ACCEPTED
	// for "whose statement about an authentication level do I believe". Since
	// the founding-signer redeem route is public and writes that record, anyone
	// holding an unredeemed invite could install the key that vouches for a
	// controller's score on the agent without ever becoming the owner.
	if owner, oerr := s.ownerFromOwnIdentity(s.thisIdentityAgentsIdentifier()); oerr == nil &&
		owner != "" {
		// The verified log first, so a rotation is followed. Nothing rewrites
		// the sealed record when an owner rotates, so asking it first would go
		// on believing a key the owner has replaced.
		if key, ok := s.ownerKeyThatMovesForward(owner); ok {
			return key, nil
		}
		// Then the sealed record, and only for the owner the log named.
		sealed, serr := s.sealedOwnerAuthority()
		if theSealCannotBeRead(serr) {
			return "", fmt.Errorf("the owner record sealed on this machine cannot be read, so nobody may speak for it: %w", serr)
		}
		if serr == nil && sealed != nil &&
			sealed.AID == owner && sealed.PublicKey != "" {
			return sealed.PublicKey, nil
		}
		return "", fmt.Errorf(
			"this identity names %s as its owner and this agent holds no key for them "+
				"that it can trust, so nobody may speak for it", owner)
	}

	// No anchor at all — a machine sealed at provisioning before it had an
	// identity. The sealed record is the only thing there is, and it was written
	// before the machine was reachable.
	sealed, serr := s.sealedOwnerAuthority()
	if theSealCannotBeRead(serr) {
		return "", fmt.Errorf("the owner record sealed on this machine cannot be read, so nobody may speak for it: %w", serr)
	}
	if serr == nil && sealed != nil && sealed.PublicKey != "" {
		return sealed.PublicKey, nil
	}
	return "", fmt.Errorf("nothing is sealed and this identity names no owner")
}

// whoThisIdentityAgentIs is this Identity Agent's own identifier, "" when it
// genuinely has none, and an error when that cannot be read. A signed request
// naming nobody is accepted only in the second case: a store that failed to
// answer must not make a founded Identity Agent look unfounded.
func (s *CoreServer) whoThisIdentityAgentIs() (string, error) {
	if s.DataStore == nil {
		return "", nil
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil {
		return "", fmt.Errorf("which identity this Identity Agent holds could not be read, so no signed request was admitted: %w", err)
	}
	if identity == nil {
		return "", nil
	}
	return identity.AID, nil
}

// thisIdentityAgentsIdentifier is this Identity Agent's own identifier, or empty when it has
// none or it cannot be read. Separated only so the caller above reads as one thought.
func (s *CoreServer) thisIdentityAgentsIdentifier() string {
	if s.DataStore == nil {
		return ""
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return ""
	}
	return identity.AID
}

// madeByController is the machine that asked for this request, when a
// controller did, or "" for the owner. Whatever a controller creates keeps
// working after the controller's grant is revoked or expires, so it is
// recorded against the controller that made it (ADR-050).
func madeByController(r *http.Request) string {
	if g, ok := TheControllerThatAsked(r); ok {
		return g.ControllerAID
	}
	return ""
}
