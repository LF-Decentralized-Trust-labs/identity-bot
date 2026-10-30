package server

import (
	"sync"

	"context"
	"database/sql"
	"identity-agent-core/activitylog"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/internal/hostlink"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
	"identity-agent-core/vault"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-chi/chi/v5"
)

// The server's side of the handle add-ons built in this module have on it
// (internal/addonhost). hostWrapper is unexported, and only addonhost asks
// for it, so nothing outside this module reaches these. Each method calls the
// server's own; none is a second copy.

func init() {
	hostlink.Of = func(core any) any {
		s, _ := core.(*CoreServer)
		return hostWrapper{s}
	}
}

type hostWrapper struct{ s *CoreServer }

// addonStates is what each add-on keeps for one server
// (addonhost.Host.AddonState).
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
func (h hostWrapper) IdentitySigningSeed() ([]byte, error)        { return h.s.identitySigningSeed() }
func (h hostWrapper) InBackground(fn func(ctx context.Context))   { h.s.inBackground(fn) }
func (h hostWrapper) InitAssetHandler() error                     { return h.s.initAssetHandler() }
func (h hostWrapper) IsVaultEntry(name string) bool               { return h.s.isVaultEntry(name) }
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
func (h hostWrapper) LogForTest(t coretypes.TB, dir string) *activitylog.Log {
	return h.s.logForTest(t, dir)
}
func (h hostWrapper) VaultForTest(dir string) *vault.CredentialVault { return h.s.vaultForTest(dir) }
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
func (hostWrapper) ControllerMinimumScore() map[string]int { return controllerMinimumScore }
func (hostWrapper) ControllerOwnerOnly() map[string]string { return controllerOwnerOnly }
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
func (hostWrapper) AControllerWorld(t coretypes.TB) (*CoreServer, *httptest.Server, string, []byte) {
	return aControllerWorld(t)
}
func (hostWrapper) AcdcOf(t coretypes.TB, s *CoreServer, said string) map[string]interface{} {
	return acdcOf(t, s, said)
}
func (hostWrapper) AgentWithDerivedIdentity(t coretypes.TB) *CoreServer {
	return agentWithDerivedIdentity(t)
}
func (hostWrapper) AnAuthorisedMachine(t coretypes.TB, s *CoreServer, grade ControllerGrade) (string, []byte) {
	return anAuthorisedMachine(t, s, grade)
}
func (hostWrapper) AnchorAfter(t coretypes.TB, n int) { anchorAfter(t, n) }
func (hostWrapper) AsThatMachine(t coretypes.TB, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request {
	return asThatMachine(t, aid, method, path, body, seed, level, measuredAt)
}
func (hostWrapper) AsThatMachineScored(t coretypes.TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time, score int) *http.Request {
	return asThatMachineScored(t, target, aid, method, path, body, seed, level, measuredAt, score)
}
func (hostWrapper) AsThatMachineTo(t coretypes.TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request {
	return asThatMachineTo(t, target, aid, method, path, body, seed, level, measuredAt)
}
func (hostWrapper) Awaiting(t coretypes.TB, s *CoreServer) (map[string]string, map[string]string) {
	return awaiting(t, s)
}
func (hostWrapper) ChainSays(t coretypes.TB, s *CoreServer) map[string]any { return chainSays(t, s) }
func (hostWrapper) CheckAsTheDevice(t coretypes.TB, s *CoreServer, req store.SigningRequest) (map[string]interface{}, error) {
	return checkAsTheDevice(t, s, req)
}
func (hostWrapper) ControllerRow(s *CoreServer, aid string) (ControllerGrant, bool, error) {
	return controllerRow(s, aid)
}
func (hostWrapper) CredentialsOf(t coretypes.TB, s *CoreServer, holder string) []store.CredentialRecord {
	return credentialsOf(t, s, holder)
}
func (hostWrapper) EveryPublicRoute() map[string]string      { return everyPublicRoute() }
func (hostWrapper) EverySessionForbidden() map[string]string { return everySessionForbidden() }
func (hostWrapper) EverythingRuns(s *CoreServer)             { everythingRuns(s) }
func (hostWrapper) Fulfil(t coretypes.TB, s *CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder {
	return fulfil(t, s, req, seed)
}
func (hostWrapper) GrantControllerRow(s *CoreServer, g ControllerGrant, now time.Time) (ControllerGrant, error) {
	return grantControllerRow(s, g, now)
}
func (hostWrapper) GrantFor(n byte, grade ControllerGrade) ControllerGrant { return grantFor(n, grade) }
func (hostWrapper) GrantWorld(t coretypes.TB) (*CoreServer, *asset.Asset)  { return grantWorld(t) }
func (hostWrapper) KeyLogVerifies(t coretypes.TB, s *CoreServer)           { keyLogVerifies(t, s) }
func (hostWrapper) LiveControllerRow(s *CoreServer, aid string, now time.Time) (ControllerGrant, bool, error) {
	return liveControllerRow(s, aid, now)
}
func (hostWrapper) Local(method string, path string, body string) *http.Request {
	return local(method, path, body)
}
func (hostWrapper) LogEventSigner(s *CoreServer) activitylog.EventSigner { return logEventSigner(s) }
func (hostWrapper) MoveTheKeyAway(t coretypes.TB, s *CoreServer) []byte  { return moveTheKeyAway(t, s) }
func (hostWrapper) NewAuthTestServer(t coretypes.TB) *CoreServer         { return newAuthTestServer(t) }
func (hostWrapper) PutControllerRow(s *CoreServer, g ControllerGrant) error {
	return putControllerRow(s, g)
}
func (hostWrapper) RebuildRouter(s *CoreServer)                    { rebuildRouter(s) }
func (hostWrapper) RecordDB(t coretypes.TB, s *CoreServer) *sql.DB { return recordDB(t, s) }
func (hostWrapper) RefusedFor(t coretypes.TB, s *CoreServer, n store.Notification, why string) {
	refusedFor(t, s, n, why)
}
func (hostWrapper) Remote(method string, path string, body string) *http.Request {
	return remote(method, path, body)
}
func (hostWrapper) ResetSeenSignatures(t coretypes.TB) { resetSeenSignatures(t) }
func (hostWrapper) ResolveWithTokens(s *CoreServer, r *http.Request) permission.CallerContext {
	return resolveWithTokens(s, r)
}
func (hostWrapper) RevokeControllerRow(s *CoreServer, aid string) error {
	return revokeControllerRow(s, aid)
}
func (hostWrapper) SealTestOwner(t coretypes.TB, s *CoreServer) ([]byte, string) {
	return sealTestOwner(t, s)
}
func (hostWrapper) SetRouter(s *CoreServer, r chi.Router) { setRouter(s, r) }
func (hostWrapper) SignInABrowser(t coretypes.TB, s *CoreServer, secret string) string {
	return signInABrowser(t, s, secret)
}
func (hostWrapper) Signed(t coretypes.TB, method string, path string, body string, seed []byte, at time.Time) *http.Request {
	return signed(t, method, path, body, seed, at)
}
func (hostWrapper) SignedFor(t coretypes.TB, target string, method string, path string, body string, seed []byte, at time.Time) *http.Request {
	return signedFor(t, target, method, path, body, seed, at)
}
func (hostWrapper) SigningPair(t coretypes.TB, b byte) ([]byte, string) { return signingPair(t, b) }
func (hostWrapper) SignsWithSeeds(e interface {
	SetEventSignature(func(aid string, key string, raw []byte) (string, error))
}, seeds ...[]byte) {
	signsWithSeeds(e, seeds...)
}
func (hostWrapper) TalkSigner() string                             { return talkSigner }
func (hostWrapper) TestOwnerSecret() string                        { return testOwnerSecret }
func (hostWrapper) TestOwnerSeed() []byte                          { return testOwnerSeed() }
func (hostWrapper) TrustLocalPeer(s *CoreServer, aid string) error { return trustLocalPeer(s, aid) }
func (hostWrapper) Waiting(t coretypes.TB, s *CoreServer) []store.SigningRequest {
	return waiting(t, s)
}
func (hostWrapper) WithController(r *http.Request, g ControllerGrant) *http.Request {
	return withController(r, g)
}
func (hostWrapper) WithOwnerSecret(s *CoreServer, secret string) *CoreServer {
	return withOwnerSecret(s, secret)
}
func (hostWrapper) WithdrawWith(t coretypes.TB, s *CoreServer, seed []byte) { withdrawWith(t, s, seed) }
func (hostWrapper) AnchorTick() time.Duration                               { return anchorTick() }
func (hostWrapper) AnchorAtLeastEvery(t coretypes.TB, d time.Duration)      { anchorAtLeastEvery(t, d) }
func (h hostWrapper) IsLiveBrowserSession(token string) bool                { return h.s.isLiveBrowserSession(token) }
func (h hostWrapper) ResolveBearerToken(r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool) {
	return h.s.resolveBearerToken(r, token, cc)
}
func (hostWrapper) BearerFrom(r *http.Request) string                { return bearerFrom(r) }
func (hostWrapper) UseAssetHandler(s *CoreServer, ah *asset.Handler) { useAssetHandler(s, ah) }
