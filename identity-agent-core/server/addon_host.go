package server

import (
	"sync"

	"context"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/internal/hostlink"
	"identity-agent-core/login"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// AddonHost is the server's side of the handle an add-on has on s (package
// addon); s may be nil for the helpers that
// need no server. It panics unless given a token hostlink.New made, so it is
// not reached by mistake. That is a safeguard, not a boundary against code an
// app chooses to link: see hostlink.Token. Each method of what it returns
// calls the server's own; none is a second copy.
//
// It is a function an add-on calls, rather than something the server
// registers when it starts, so that a program that includes no add-on (the
// phone core, the core's own desktop program) links none of it, nor the test fixtures
// it hands to the add-ons' tests.
func AddonHost(s *CoreServer, t hostlink.Token) any {
	hostlink.Refuse(t, "server.AddonHost")
	return hostWrapper{s}
}

type hostWrapper struct{ s *CoreServer }

// addonStates is what each add-on keeps for one server
// (addon.Host.AddonState).
type addonStates struct{ m sync.Map }

func (h hostWrapper) AddonState(key any, make func() any) any {
	if v, ok := h.s.addonStates.m.Load(key); ok {
		return v
	}
	v, _ := h.s.addonStates.m.LoadOrStore(key, make())
	return v
}

func (h hostWrapper) AnchorRecord() (bool, error)  { return h.s.anchorRecord() }
func (h hostWrapper) AssetHandler() *asset.Handler { return h.s.assetHandler }
func (h hostWrapper) AuthorityOf(r *http.Request) (coretypes.Authority, func(), error) {
	return h.s.authorityOf(r)
}
func (h hostWrapper) AwaitingFor(holder string, pending bool) string {
	return h.s.awaitingFor(holder, pending)
}
func (h hostWrapper) BindSigner(aid string, signer string) (ControllerGrant, error) {
	return h.s.bindSigner(aid, signer)
}
func (h hostWrapper) BuildRouter(flutterWebDir string) chi.Router {
	return h.s.buildRouter(flutterWebDir)
}
func (h hostWrapper) CredentialLog(registrySAID string, acdcSAID string) ([]string, string, error) {
	return h.s.credentialLog(registrySAID, acdcSAID)
}
func (h hostWrapper) DelegatedFromHere(aid string, e coretypes.OwnEvidence) error {
	return h.s.delegatedFromHere(aid, e)
}
func (h hostWrapper) EngineSigns() { h.s.engineSigns() }
func (h hostWrapper) EnrichProvenCaller(caller *permission.CallerContext) {
	h.s.enrichProvenCaller(caller)
}
func (h hostWrapper) FindAgentAssetByAID(aid string) *coretypes.AgentRef {
	return h.s.findAgentAssetByAID(aid)
}
func (h hostWrapper) FindCapabilityGrant(aid string) *coretypes.GrantRef {
	return h.s.findCapabilityGrant(aid)
}
func (h hostWrapper) GetPublicURL(r *http.Request) string { return h.s.getPublicURL(r) }
func (h hostWrapper) GrantController(g ControllerGrant, now time.Time, by coretypes.Authority) (ControllerGrant, error) {
	return h.s.grantController(g, now, by)
}
func (h hostWrapper) GrantsHeldBy(agentAID string, usableOnly bool) []store.CredentialRecord {
	return h.s.grantsHeldBy(agentAID, usableOnly)
}
func (h hostWrapper) HandleDIDCommInbound(w http.ResponseWriter, r *http.Request) {
	h.s.handleDIDCommInbound(w, r)
}
func (h hostWrapper) HandleGrantController(w http.ResponseWriter, r *http.Request) {
	h.s.handleGrantController(w, r)
}
func (h hostWrapper) HasBrowserSession(r *http.Request) bool      { return h.s.hasBrowserSession(r) }
func (h hostWrapper) HoldTheRecord() (string, bool, bool, func()) { return h.s.holdTheRecord() }
func (h hostWrapper) SignAsTheIdentity(message []byte) (string, error) {
	seed, err := h.s.identitySigningSeed()
	if err != nil {
		return "", err
	}
	return login.SignString(string(message), seed)
}
func (h hostWrapper) InBackground(fn func(ctx context.Context)) { h.s.inBackground(fn) }
func (h hostWrapper) InitAssetHandler() error                   { return h.s.initAssetHandler() }
func (h hostWrapper) IsVaultEntry(name string) bool             { return h.s.isVaultEntry(name) }
func (h hostWrapper) IssueAssetCredential(kind *schemas.AssetGrant, holder string, issuer string, claims map[string]interface{}, expiry string, by coretypes.Authority) (string, error) {
	return h.s.issueAssetCredential(kind, holder, issuer, claims, expiry, by)
}
func (h hostWrapper) IssueCapabilityGrant(agent *asset.Asset, by coretypes.Authority) (string, error) {
	return h.s.issueCapabilityGrant(agent, by)
}
func (h hostWrapper) IssuedUnderFirstVersionTooLate(rec *store.CredentialRecord) bool {
	return h.s.issuedUnderFirstVersionTooLate(rec)
}
func (h hostWrapper) KeyCanSign() error                             { return h.s.keyCanSign() }
func (h hostWrapper) KeyIsElsewhere() bool                          { return h.s.keyIsElsewhere() }
func (h hostWrapper) KeySetFor(aid string) (*didcomm.KeySet, error) { return h.s.keySetFor(aid) }
func (h hostWrapper) NoteRecorded()                                 { h.s.noteRecorded() }
func (h hostWrapper) OwnAgentAtArrival(aid string, did *didcomm.DID) (string, error) {
	return h.s.ownAgentAtArrival(aid, did)
}
func (h hostWrapper) OwnerAuthority() (*OwnerAuthority, error) { return h.s.ownerAuthority() }
func (h hostWrapper) PartyConversation(convID string, party string) string {
	return h.s.partyConversation(convID, party)
}
func (h hostWrapper) PersonStillStands(p coretypes.Signer) bool { return h.s.personStillStands(p) }
func (h hostWrapper) ProvedSender(n store.Notification) (*didcomm.JWM, string, error) {
	return h.s.provedSender(n)
}
func (h hostWrapper) RecordDeliveryOnce(cc permission.CallerContext, messageID string, host string) {
	h.s.recordDeliveryOnce(cc, messageID, host)
}
func (h hostWrapper) RequireOwner(w http.ResponseWriter, r *http.Request) bool {
	return h.s.requireOwner(w, r)
}
func (h hostWrapper) ResolveCaller(r *http.Request) permission.CallerContext {
	return h.s.resolveCaller(r)
}
func (h hostWrapper) RevokeController(aid string) error     { return h.s.revokeController(aid) }
func (h hostWrapper) Router() chi.Router                    { return h.s.router }
func (h hostWrapper) RowIsItsGrant(g ControllerGrant) error { return h.s.rowIsItsGrant(g) }
func (h hostWrapper) StoredKelForVerifying(aid string) ([]map[string]interface{}, error) {
	return h.s.storedKelForVerifying(aid)
}
func (h hostWrapper) TheOwner() (string, bool) { return h.s.theOwner() }
func (h hostWrapper) ThePersonAsking(r *http.Request) (coretypes.Signer, *coretypes.ControllerProof, error) {
	return h.s.thePersonAsking(r)
}
func (h hostWrapper) ThisIdentityAgentsIdentifier() string       { return h.s.thisIdentityAgentsIdentifier() }
func (h hostWrapper) VerifyOwnerSignature(r *http.Request) error { return h.s.verifyOwnerSignature(r) }
func (h hostWrapper) VerifyRequestEnvelope(r *http.Request, method string, params []byte, caller *permission.CallerContext) error {
	return h.s.verifyRequestEnvelope(r, method, params, caller)
}
func (h hostWrapper) WhoThisIdentityAgentIs() (string, error) { return h.s.whoThisIdentityAgentIs() }
func (h hostWrapper) WithdrawControllerGrant(said string) error {
	return h.s.withdrawControllerGrant(said)
}
func (h hostWrapper) WithdrawCredential(rec *store.CredentialRecord) (bool, string, error) {
	return h.s.withdrawCredential(rec)
}
func (hostWrapper) ApplyCallerWhy(r *http.Request, cc *permission.CallerContext) {
	applyCallerWhy(r, cc)
}
func (hostWrapper) AwaitingPhrase(pending bool) string { return awaitingPhrase(pending) }
func (hostWrapper) BearerToken(r *http.Request) string { return bearerToken(r) }
func (hostWrapper) CanonicalControllerRequest(controllerAID string, target string, method string, path string, timestamp string, authenticated authprovider.Result, body []byte) string {
	return canonicalControllerRequest(controllerAID, target, method, path, timestamp, authenticated, body)
}
func (hostWrapper) CanonicalOwnerRequest(target string, method string, path string, timestamp string, body []byte) string {
	return canonicalOwnerRequest(target, method, path, timestamp, body)
}
func (hostWrapper) CanonicalRequestString(method string, path string, timestamp string, body []byte) string {
	return canonicalRequestString(method, path, timestamp, body)
}
func (hostWrapper) CapabilityGrantSchemaSAID() string      { return capabilityGrantSchemaSAID }
func (hostWrapper) CapabilityGrantSchemaSAIDs() []string   { return capabilityGrantSchemaSAIDs }
func (hostWrapper) ClampWhy(v string) string               { return clampWhy(v) }
func (hostWrapper) ControllerLearnsWhoItActsFor() string   { return controllerLearnsWhoItActsFor }
func (hostWrapper) ControllerMinimumScore() map[string]int { return everyControllerMinimumScore() }
func (hostWrapper) ControllerOwnerOnly() map[string]string { return everyControllerOwnerOnly() }
func (hostWrapper) CredentialStatusWithdrawing() string    { return credentialStatusWithdrawing }
func (hostWrapper) DenyAuthorization(w http.ResponseWriter, detail string) {
	denyAuthorization(w, detail)
}
func (hostWrapper) ErrKeyElsewhere() error                      { return errKeyElsewhere }
func (hostWrapper) ErrKeyUnavailable() error                    { return errKeyUnavailable }
func (hostWrapper) HeaderControllerFor() string                 { return headerControllerFor }
func (hostWrapper) HeaderOwnerFor() string                      { return headerOwnerFor }
func (hostWrapper) HeaderOwnerSig() string                      { return headerOwnerSig }
func (hostWrapper) HeaderOwnerTimestamp() string                { return headerOwnerTimestamp }
func (hostWrapper) HeaderSealedFrom() string                    { return headerSealedFrom }
func (hostWrapper) IsUsableStatus(status string) bool           { return isUsableStatus(status) }
func (hostWrapper) IssuedAt(c store.CredentialRecord) time.Time { return issuedAt(c) }
func (hostWrapper) JSONError(w http.ResponseWriter, message string, status int) {
	jsonError(w, message, status)
}
func (hostWrapper) JSONResponse(w http.ResponseWriter, data interface{}) { jsonResponse(w, data) }
func (hostWrapper) KeysOwn() string                                      { return keysOwn }
func (hostWrapper) MadeByController(r *http.Request) string              { return madeByController(r) }
func (hostWrapper) NonNilConstraints(c map[string]interface{}) map[string]interface{} {
	return nonNilConstraints(c)
}
func (hostWrapper) OwnerAuthorityFile() string { return ownerAuthorityFile }
func (hostWrapper) OwnerSigned() string        { return ownerSigned }
func (hostWrapper) ReadInvocationSignerRecord(dataDir string) (coretypes.LogSignerRecord, bool, error) {
	return readInvocationSignerRecord(dataDir)
}
func (hostWrapper) ReadSignedBody(r *http.Request) ([]byte, error) { return readSignedBody(r) }
func (hostWrapper) RememberSignature(sig string, now time.Time) bool {
	return rememberSignature(sig, now)
}
func (hostWrapper) RequestCorrelationID(r *http.Request) string { return requestCorrelationID(r) }
func (hostWrapper) RequiresTheKeyItself(method string, pattern string) (string, bool) {
	return requiresTheKeyItself(method, pattern)
}
func (hostWrapper) SameJSONValue(a interface{}, b interface{}) bool { return sameJSONValue(a, b) }
func (hostWrapper) SealedRemoteAddr() string                        { return sealedRemoteAddr }
func (hostWrapper) SignEventBytes(raw []byte, seed []byte) (string, error) {
	return signEventBytes(raw, seed)
}
func (hostWrapper) TheGateAdmittedTheOwner(r *http.Request) bool { return theGateAdmittedTheOwner(r) }
func (hostWrapper) UnknownRouteRefusal() string                  { return unknownRouteRefusal }
func (hostWrapper) WriteError(w http.ResponseWriter, status int, errMsg string, details string) {
	writeError(w, status, errMsg, details)
}
func (hostWrapper) WriteJSON(w http.ResponseWriter, v interface{}) { writeJSON(w, v) }
func (hostWrapper) WriteJSONStatus(w http.ResponseWriter, status int, v interface{}) {
	writeJSONStatus(w, status, v)
}
func (hostWrapper) AnchorTick() time.Duration                { return anchorTick() }
func (h hostWrapper) IsLiveBrowserSession(token string) bool { return h.s.isLiveBrowserSession(token) }
func (h hostWrapper) ResolveBearerToken(r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool) {
	return h.s.resolveBearerToken(r, token, cc)
}
func (hostWrapper) BearerFrom(r *http.Request) string { return bearerFrom(r) }
