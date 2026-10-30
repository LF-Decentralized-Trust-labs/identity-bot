// Package addonhost is the handle an add-on built in this module has on the
// core: the parts of the server it needs that are not the server's public
// API.
//
// An add-on in a package of its own registers with server.RegisterAddon and
// is handed the *server.CoreServer it runs on. What it may do with that
// server beyond its exported fields and methods is exactly this: Host, for
// one server, and Helpers, for what needs none. The server implements both
// with an unexported type it returns from server.AddonHost, which asks for a
// hostlink.Token that nothing outside this module can name; so nothing
// outside this module reaches them, and a program that includes no add-on
// links none of it. Nothing here is a second copy: each method calls the
// server's own.
//
// Fixtures are the worlds the core's own tests build, for the add-ons'
// tests, from server.AddonFixtures. Only a test asks for them, so no program
// links them.
package addonhost

import (
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
	"identity-agent-core/server"
	"identity-agent-core/store"
	"identity-agent-core/vault"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-chi/chi/v5"
)

// Of is the handle on s.
func Of(s *server.CoreServer) Host { return server.AddonHost(s, hostlink.Token{}).(Host) }

// TestFixtures are the core's test fixtures, for the add-ons' tests. Only a
// test calls it, so no program links them.
func TestFixtures() Fixtures { return server.AddonFixtures(hostlink.Token{}).(Fixtures) }

// Shared is the handle on what needs no server.
func Shared() Helpers { return server.AddonHost(nil, hostlink.Token{}).(Helpers) }

// Host is what an add-on may ask of the server it runs on.
type Host interface {
	// AddonState is what an add-on keeps for this server under key, made by
	// make the first time it is asked for. Keep a key of an unexported type
	// of the add-on's own, so no two add-ons share one.
	AddonState(key any, make func() any) any

	AnchorRecord() (bool, error)
	AssetHandler() *asset.Handler
	AuthorityOf(r *http.Request) (coretypes.Authority, func(), error)
	AwaitingFor(holder string, pending bool) string
	BindSigner(aid string, signer string) (server.ControllerGrant, error)
	BuildRouter(flutterWebDir string) chi.Router
	CredentialLog(registrySAID string, acdcSAID string) ([]string, string, error)
	DelegatedFromHere(aid string, e coretypes.OwnEvidence) error
	EngineSigns()
	EnrichProvenCaller(caller *permission.CallerContext)
	FindAgentAssetByAID(aid string) *coretypes.AgentRef
	FindCapabilityGrant(aid string) *coretypes.GrantRef
	GetPublicURL(r *http.Request) string
	GrantController(g server.ControllerGrant, now time.Time, by coretypes.Authority) (server.ControllerGrant, error)
	GrantsHeldBy(agentAID string, usableOnly bool) []store.CredentialRecord
	HandleDIDCommInbound(w http.ResponseWriter, r *http.Request)
	HandleGrantController(w http.ResponseWriter, r *http.Request)
	HasBrowserSession(r *http.Request) bool
	HoldTheRecord() (string, bool, bool, func())
	IdentitySigningSeed() ([]byte, error)
	InBackground(fn func(ctx context.Context))
	InitAssetHandler() error
	IsLiveBrowserSession(token string) bool
	IsVaultEntry(name string) bool
	IssueAssetCredential(kind *schemas.AssetGrant, holder string, issuer string, claims map[string]interface{}, expiry string, by coretypes.Authority) (string, error)
	IssueCapabilityGrant(agent *asset.Asset, by coretypes.Authority) (string, error)
	IssuedUnderFirstVersionTooLate(rec *store.CredentialRecord) bool
	KeyCanSign() error
	KeyIsElsewhere() bool
	KeySetFor(aid string) (*didcomm.KeySet, error)
	NoteRecorded()
	OwnAgentAtArrival(aid string, did *didcomm.DID) (string, error)
	OwnerAuthority() (*server.OwnerAuthority, error)
	PartyConversation(convID string, party string) string
	PersonStillStands(p coretypes.Signer) bool
	ProvedSender(n store.Notification) (*didcomm.JWM, string, error)
	RecordDeliveryOnce(cc permission.CallerContext, messageID string, host string)
	RequireOwner(w http.ResponseWriter, r *http.Request) bool
	ResolveBearerToken(r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool)
	ResolveCaller(r *http.Request) permission.CallerContext
	RevokeController(aid string) error
	Router() chi.Router
	RowIsItsGrant(g server.ControllerGrant) error
	StoredKelForVerifying(aid string) ([]map[string]interface{}, error)
	TheOwner() (string, bool)
	ThePersonAsking(r *http.Request) (coretypes.Signer, *coretypes.ControllerProof, error)
	ThisIdentityAgentsIdentifier() string
	VerifyOwnerSignature(r *http.Request) error
	VerifyRequestEnvelope(r *http.Request, method string, params []byte, caller *permission.CallerContext) error
	WhoThisIdentityAgentIs() (string, error)
	WithdrawControllerGrant(said string) error
	WithdrawCredential(rec *store.CredentialRecord) (bool, string, error)
}

// Helpers are the core's own helpers an add-on uses: writing answers, the
// header names and request forms the core signs and checks, and the like.
type Helpers interface {
	AnchorTick() time.Duration
	ApplyCallerWhy(r *http.Request, cc *permission.CallerContext)
	AwaitingPhrase(pending bool) string
	BearerFrom(r *http.Request) string
	BearerToken(r *http.Request) string
	CanonicalControllerRequest(controllerAID string, target string, method string, path string, timestamp string, authenticated authprovider.Result, body []byte) string
	CanonicalOwnerRequest(target string, method string, path string, timestamp string, body []byte) string
	CanonicalRequestString(method string, path string, timestamp string, body []byte) string
	CapabilityGrantSchemaSAID() string
	CapabilityGrantSchemaSAIDs() []string
	ClampWhy(v string) string
	ControllerLearnsWhoItActsFor() string
	// ControllerMinimumScore and ControllerOwnerOnly are copies of the rules
	// for a controller in force, the core's and every add-on's: changing one
	// changes nothing.
	ControllerMinimumScore() map[string]int
	ControllerOwnerOnly() map[string]string
	CredentialStatusWithdrawing() string
	DenyAuthorization(w http.ResponseWriter, detail string)
	ErrKeyElsewhere() error
	ErrKeyUnavailable() error
	HeaderControllerFor() string
	HeaderOwnerFor() string
	HeaderOwnerSig() string
	HeaderOwnerTimestamp() string
	HeaderSealedFrom() string
	IsUsableStatus(status string) bool
	IssuedAt(c store.CredentialRecord) time.Time
	JSONError(w http.ResponseWriter, message string, status int)
	JSONResponse(w http.ResponseWriter, data interface{})
	KeysOwn() string
	MadeByController(r *http.Request) string
	NonNilConstraints(c map[string]interface{}) map[string]interface{}
	OwnerAuthorityFile() string
	OwnerSigned() string
	ReadInvocationSignerRecord(dataDir string) (coretypes.LogSignerRecord, bool, error)
	ReadSignedBody(r *http.Request) ([]byte, error)
	RememberSignature(sig string, now time.Time) bool
	RequestCorrelationID(r *http.Request) string
	RequiresTheKeyItself(method string, pattern string) (string, bool)
	SameJSONValue(a interface{}, b interface{}) bool
	SealedRemoteAddr() string
	SignEventBytes(raw []byte, seed []byte) (string, error)
	TheGateAdmittedTheOwner(r *http.Request) bool
	UnknownRouteRefusal() string
	WriteError(w http.ResponseWriter, status int, errMsg string, details string)
	WriteJSON(w http.ResponseWriter, v interface{})
	WriteJSONStatus(w http.ResponseWriter, status int, v interface{})
}

// Fixtures are the worlds the core's tests build, for the add-ons' tests:
// an organisation founded as startup finds it, a controller paired and
// granted, a request signed as a machine signs it.
type Fixtures interface {
	LogForTest(s *server.CoreServer, t coretypes.TB, dir string) *activitylog.Log
	VaultForTest(s *server.CoreServer, dir string) *vault.CredentialVault
	AControllerWorld(t coretypes.TB) (*server.CoreServer, *httptest.Server, string, []byte)
	AcdcOf(t coretypes.TB, s *server.CoreServer, said string) map[string]interface{}
	AgentWithDerivedIdentity(t coretypes.TB) *server.CoreServer
	AnAuthorisedMachine(t coretypes.TB, s *server.CoreServer, grade server.ControllerGrade) (string, []byte)
	AnchorAfter(t coretypes.TB, n int)
	AnchorAtLeastEvery(t coretypes.TB, d time.Duration)
	AsThatMachine(t coretypes.TB, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request
	AsThatMachineScored(t coretypes.TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time, score int) *http.Request
	AsThatMachineTo(t coretypes.TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request
	Awaiting(t coretypes.TB, s *server.CoreServer) (map[string]string, map[string]string)
	ChainSays(t coretypes.TB, s *server.CoreServer) map[string]any
	CheckAsTheDevice(t coretypes.TB, s *server.CoreServer, req store.SigningRequest) (map[string]interface{}, error)
	ControllerRow(s *server.CoreServer, aid string) (server.ControllerGrant, bool, error)
	CredentialsOf(t coretypes.TB, s *server.CoreServer, holder string) []store.CredentialRecord
	ControllerNeedsScore(t coretypes.TB, route string, score int)
	EntriesForRoutesNotItsOwn(s *server.CoreServer) []string
	EveryPublicRoute() map[string]string
	EverySessionForbidden() map[string]string
	EverythingRuns(s *server.CoreServer)
	Fulfil(t coretypes.TB, s *server.CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder
	GrantControllerRow(s *server.CoreServer, g server.ControllerGrant, now time.Time) (server.ControllerGrant, error)
	GrantFor(n byte, grade server.ControllerGrade) server.ControllerGrant
	GrantWorld(t coretypes.TB) (*server.CoreServer, *asset.Asset)
	KeyLogVerifies(t coretypes.TB, s *server.CoreServer)
	LiveControllerRow(s *server.CoreServer, aid string, now time.Time) (server.ControllerGrant, bool, error)
	Local(method string, path string, body string) *http.Request
	LogEventSigner(s *server.CoreServer) activitylog.EventSigner
	MoveTheKeyAway(t coretypes.TB, s *server.CoreServer) []byte
	NewAuthTestServer(t coretypes.TB) *server.CoreServer
	PutControllerRow(s *server.CoreServer, g server.ControllerGrant) error
	RebuildRouter(s *server.CoreServer)
	RecordDB(t coretypes.TB, s *server.CoreServer) *sql.DB
	RefusedFor(t coretypes.TB, s *server.CoreServer, n store.Notification, why string)
	Remote(method string, path string, body string) *http.Request
	ResetSeenSignatures(t coretypes.TB)
	ResolveWithTokens(s *server.CoreServer, r *http.Request) permission.CallerContext
	RevokeControllerRow(s *server.CoreServer, aid string) error
	SealTestOwner(t coretypes.TB, s *server.CoreServer) ([]byte, string)
	SetRouter(s *server.CoreServer, r chi.Router)
	SignInABrowser(t coretypes.TB, s *server.CoreServer, secret string) string
	Signed(t coretypes.TB, method string, path string, body string, seed []byte, at time.Time) *http.Request
	SignedFor(t coretypes.TB, target string, method string, path string, body string, seed []byte, at time.Time) *http.Request
	SigningPair(t coretypes.TB, b byte) ([]byte, string)
	SignsWithSeeds(e interface {
		SetEventSignature(func(aid string, key string, raw []byte) (string, error))
	}, seeds ...[]byte)
	TalkSigner() string
	TestOwnerSecret() string
	TestOwnerSeed() []byte
	TrustLocalPeer(s *server.CoreServer, aid string) error
	Waiting(t coretypes.TB, s *server.CoreServer) []store.SigningRequest
	WithController(r *http.Request, g server.ControllerGrant) *http.Request
	WithOwnerSecret(s *server.CoreServer, secret string) *server.CoreServer
	UseAssetHandler(s *server.CoreServer, ah *asset.Handler)
	WithdrawWith(t coretypes.TB, s *server.CoreServer, seed []byte)
}
