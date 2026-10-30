package server

import (
	"database/sql"
	"identity-agent-core/activitylog"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/internal/hostlink"
	"identity-agent-core/permission"
	"identity-agent-core/store"
	"identity-agent-core/vault"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-chi/chi/v5"
)

// AddonFixtures are the core's test fixtures (fixtures_for_tests.go), for
// the tests of the add-ons built in this module (addonhost.TestFixtures). It
// asks for a hostlink.Token, which nothing outside this module can name. Only
// a test calls it, so no program links it or the fixtures.
func AddonFixtures(_ hostlink.Token) any { return fixtureWrapper{} }

type fixtureWrapper struct{}

func (fixtureWrapper) LogForTest(s *CoreServer, t coretypes.TB, dir string) *activitylog.Log {
	return s.logForTest(t, dir)
}
func (fixtureWrapper) VaultForTest(s *CoreServer, dir string) *vault.CredentialVault {
	return s.vaultForTest(dir)
}
func (fixtureWrapper) AControllerWorld(t coretypes.TB) (*CoreServer, *httptest.Server, string, []byte) {
	return aControllerWorld(t)
}
func (fixtureWrapper) AcdcOf(t coretypes.TB, s *CoreServer, said string) map[string]interface{} {
	return acdcOf(t, s, said)
}
func (fixtureWrapper) AgentWithDerivedIdentity(t coretypes.TB) *CoreServer {
	return agentWithDerivedIdentity(t)
}
func (fixtureWrapper) AnAuthorisedMachine(t coretypes.TB, s *CoreServer, grade ControllerGrade) (string, []byte) {
	return anAuthorisedMachine(t, s, grade)
}
func (fixtureWrapper) AnchorAfter(t coretypes.TB, n int) { anchorAfter(t, n) }
func (fixtureWrapper) AsThatMachine(t coretypes.TB, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request {
	return asThatMachine(t, aid, method, path, body, seed, level, measuredAt)
}
func (fixtureWrapper) AsThatMachineScored(t coretypes.TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time, score int) *http.Request {
	return asThatMachineScored(t, target, aid, method, path, body, seed, level, measuredAt, score)
}
func (fixtureWrapper) AsThatMachineTo(t coretypes.TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request {
	return asThatMachineTo(t, target, aid, method, path, body, seed, level, measuredAt)
}
func (fixtureWrapper) Awaiting(t coretypes.TB, s *CoreServer) (map[string]string, map[string]string) {
	return awaiting(t, s)
}
func (fixtureWrapper) ChainSays(t coretypes.TB, s *CoreServer) map[string]any { return chainSays(t, s) }
func (fixtureWrapper) CheckAsTheDevice(t coretypes.TB, s *CoreServer, req store.SigningRequest) (map[string]interface{}, error) {
	return checkAsTheDevice(t, s, req)
}
func (fixtureWrapper) ControllerRow(s *CoreServer, aid string) (ControllerGrant, bool, error) {
	return controllerRow(s, aid)
}
func (fixtureWrapper) CredentialsOf(t coretypes.TB, s *CoreServer, holder string) []store.CredentialRecord {
	return credentialsOf(t, s, holder)
}
func (fixtureWrapper) EveryPublicRoute() map[string]string      { return everyPublicRoute() }
func (fixtureWrapper) EverySessionForbidden() map[string]string { return everySessionForbidden() }
func (fixtureWrapper) EverythingRuns(s *CoreServer)             { everythingRuns(s) }
func (fixtureWrapper) Fulfil(t coretypes.TB, s *CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder {
	return fulfil(t, s, req, seed)
}
func (fixtureWrapper) GrantControllerRow(s *CoreServer, g ControllerGrant, now time.Time) (ControllerGrant, error) {
	return grantControllerRow(s, g, now)
}
func (fixtureWrapper) GrantFor(n byte, grade ControllerGrade) ControllerGrant {
	return grantFor(n, grade)
}
func (fixtureWrapper) GrantWorld(t coretypes.TB) (*CoreServer, *asset.Asset) { return grantWorld(t) }
func (fixtureWrapper) KeyLogVerifies(t coretypes.TB, s *CoreServer)          { keyLogVerifies(t, s) }
func (fixtureWrapper) LiveControllerRow(s *CoreServer, aid string, now time.Time) (ControllerGrant, bool, error) {
	return liveControllerRow(s, aid, now)
}
func (fixtureWrapper) Local(method string, path string, body string) *http.Request {
	return local(method, path, body)
}
func (fixtureWrapper) LogEventSigner(s *CoreServer) activitylog.EventSigner { return logEventSigner(s) }
func (fixtureWrapper) MoveTheKeyAway(t coretypes.TB, s *CoreServer) []byte {
	return moveTheKeyAway(t, s)
}
func (fixtureWrapper) NewAuthTestServer(t coretypes.TB) *CoreServer { return newAuthTestServer(t) }
func (fixtureWrapper) PutControllerRow(s *CoreServer, g ControllerGrant) error {
	return putControllerRow(s, g)
}
func (fixtureWrapper) RebuildRouter(s *CoreServer)                    { rebuildRouter(s) }
func (fixtureWrapper) RecordDB(t coretypes.TB, s *CoreServer) *sql.DB { return recordDB(t, s) }
func (fixtureWrapper) RefusedFor(t coretypes.TB, s *CoreServer, n store.Notification, why string) {
	refusedFor(t, s, n, why)
}
func (fixtureWrapper) Remote(method string, path string, body string) *http.Request {
	return remote(method, path, body)
}
func (fixtureWrapper) ResetSeenSignatures(t coretypes.TB) { resetSeenSignatures(t) }
func (fixtureWrapper) ResolveWithTokens(s *CoreServer, r *http.Request) permission.CallerContext {
	return resolveWithTokens(s, r)
}
func (fixtureWrapper) RevokeControllerRow(s *CoreServer, aid string) error {
	return revokeControllerRow(s, aid)
}
func (fixtureWrapper) SealTestOwner(t coretypes.TB, s *CoreServer) ([]byte, string) {
	return sealTestOwner(t, s)
}
func (fixtureWrapper) SetRouter(s *CoreServer, r chi.Router) { setRouter(s, r) }
func (fixtureWrapper) SignInABrowser(t coretypes.TB, s *CoreServer, secret string) string {
	return signInABrowser(t, s, secret)
}
func (fixtureWrapper) Signed(t coretypes.TB, method string, path string, body string, seed []byte, at time.Time) *http.Request {
	return signed(t, method, path, body, seed, at)
}
func (fixtureWrapper) SignedFor(t coretypes.TB, target string, method string, path string, body string, seed []byte, at time.Time) *http.Request {
	return signedFor(t, target, method, path, body, seed, at)
}
func (fixtureWrapper) SigningPair(t coretypes.TB, b byte) ([]byte, string) { return signingPair(t, b) }
func (fixtureWrapper) SignsWithSeeds(e interface {
	SetEventSignature(func(aid string, key string, raw []byte) (string, error))
}, seeds ...[]byte) {
	signsWithSeeds(e, seeds...)
}
func (fixtureWrapper) TalkSigner() string                             { return talkSigner }
func (fixtureWrapper) TestOwnerSecret() string                        { return testOwnerSecret }
func (fixtureWrapper) TestOwnerSeed() []byte                          { return testOwnerSeed() }
func (fixtureWrapper) TrustLocalPeer(s *CoreServer, aid string) error { return trustLocalPeer(s, aid) }
func (fixtureWrapper) Waiting(t coretypes.TB, s *CoreServer) []store.SigningRequest {
	return waiting(t, s)
}
func (fixtureWrapper) WithController(r *http.Request, g ControllerGrant) *http.Request {
	return withController(r, g)
}
func (fixtureWrapper) WithOwnerSecret(s *CoreServer, secret string) *CoreServer {
	return withOwnerSecret(s, secret)
}
func (fixtureWrapper) WithdrawWith(t coretypes.TB, s *CoreServer, seed []byte) {
	withdrawWith(t, s, seed)
}
func (fixtureWrapper) AnchorAtLeastEvery(t coretypes.TB, d time.Duration) { anchorAtLeastEvery(t, d) }
func (fixtureWrapper) UseAssetHandler(s *CoreServer, ah *asset.Handler)   { useAssetHandler(s, ah) }
func (fixtureWrapper) EntriesForRoutesNotItsOwn(s *CoreServer) []string {
	return entriesForRoutesNotItsOwn(s)
}
func (fixtureWrapper) ControllerNeedsScore(t coretypes.TB, route string, score int) {
	controllerNeedsScore(t, route, score)
}
