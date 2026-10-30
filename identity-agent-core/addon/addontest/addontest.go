// Package addontest is the core's own test fixtures, for an add-on's tests:
// the worlds the core's tests build, handed to tests written outside the
// core. Only a test imports it. A program that imports it links fixtures that
// make test owners and move keys, so it is never imported by a program, and
// the core's own programs are checked to link none of it.
//
// Like the handle in package addon, it is reached only through this package
// (server.AddonFixtures asks for the core's token), as a safeguard and not a
// security boundary.
package addontest

import (
	"database/sql"
	"identity-agent-core/activitylog"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/internal/hostlink"
	"identity-agent-core/permission"
	"identity-agent-core/server"
	"identity-agent-core/store"
	"identity-agent-core/vault"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-chi/chi/v5"
)

// New is the core's test fixtures.
func New() Fixtures { return server.AddonFixtures(hostlink.New()).(Fixtures) }

// TB is what a fixture asks of the test running it: what *testing.T gives.
type TB = coretypes.TB

// Fixtures are the worlds the core's tests build, for the add-ons' tests:
// an organisation founded as startup finds it, a controller paired and
// granted, a request signed as a machine signs it.
type Fixtures interface {
	LogForTest(s *server.CoreServer, t TB, dir string) *activitylog.Log
	VaultForTest(s *server.CoreServer, dir string) *vault.CredentialVault
	AControllerWorld(t TB) (*server.CoreServer, *httptest.Server, string, []byte)
	AcdcOf(t TB, s *server.CoreServer, said string) map[string]interface{}
	AgentWithDerivedIdentity(t TB) *server.CoreServer
	AnAuthorisedMachine(t TB, s *server.CoreServer, grade server.ControllerGrade) (string, []byte)
	AnchorAfter(t TB, n int)
	AnchorAtLeastEvery(t TB, d time.Duration)
	AsThatMachine(t TB, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request
	AsThatMachineScored(t TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time, score int) *http.Request
	AsThatMachineTo(t TB, target string, aid string, method string, path string, body string, seed []byte, level authprovider.Level, measuredAt time.Time) *http.Request
	Awaiting(t TB, s *server.CoreServer) (map[string]string, map[string]string)
	ChainSays(t TB, s *server.CoreServer) map[string]any
	CheckAsTheDevice(t TB, s *server.CoreServer, req store.SigningRequest) (map[string]interface{}, error)
	ControllerRow(s *server.CoreServer, aid string) (server.ControllerGrant, bool, error)
	CredentialsOf(t TB, s *server.CoreServer, holder string) []store.CredentialRecord
	ControllerNeedsScore(t TB, route string, score int)
	EntriesForRoutesNotItsOwn(s *server.CoreServer) []string
	EveryPublicRoute() map[string]string
	EverySessionForbidden() map[string]string
	EverythingRuns(s *server.CoreServer)
	Fulfil(t TB, s *server.CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder
	GrantControllerRow(s *server.CoreServer, g server.ControllerGrant, now time.Time) (server.ControllerGrant, error)
	GrantFor(n byte, grade server.ControllerGrade) server.ControllerGrant
	GrantWorld(t TB) (*server.CoreServer, *asset.Asset)
	KeyLogVerifies(t TB, s *server.CoreServer)
	LiveControllerRow(s *server.CoreServer, aid string, now time.Time) (server.ControllerGrant, bool, error)
	Local(method string, path string, body string) *http.Request
	LogEventSigner(s *server.CoreServer) activitylog.EventSigner
	MoveTheKeyAway(t TB, s *server.CoreServer) []byte
	NewAuthTestServer(t TB) *server.CoreServer
	PutControllerRow(s *server.CoreServer, g server.ControllerGrant) error
	RebuildRouter(s *server.CoreServer)
	RecordDB(t TB, s *server.CoreServer) *sql.DB
	RefusedFor(t TB, s *server.CoreServer, n store.Notification, why string)
	Remote(method string, path string, body string) *http.Request
	ResetSeenSignatures(t TB)
	ResolveWithTokens(s *server.CoreServer, r *http.Request) permission.CallerContext
	RevokeControllerRow(s *server.CoreServer, aid string) error
	SealTestOwner(t TB, s *server.CoreServer) ([]byte, string)
	SetRouter(s *server.CoreServer, r chi.Router)
	SignInABrowser(t TB, s *server.CoreServer, secret string) string
	Signed(t TB, method string, path string, body string, seed []byte, at time.Time) *http.Request
	SignedFor(t TB, target string, method string, path string, body string, seed []byte, at time.Time) *http.Request
	SigningPair(t TB, b byte) ([]byte, string)
	SignsWithSeeds(e interface {
		SetEventSignature(func(aid string, key string, raw []byte) (string, error))
	}, seeds ...[]byte)
	TalkSigner() string
	TestOwnerSecret() string
	TestOwnerSeed() []byte
	TrustLocalPeer(s *server.CoreServer, aid string) error
	Waiting(t TB, s *server.CoreServer) []store.SigningRequest
	WithController(r *http.Request, g server.ControllerGrant) *http.Request
	WithOwnerSecret(s *server.CoreServer, secret string) *server.CoreServer
	UseAssetHandler(s *server.CoreServer, ah *asset.Handler)
	WithdrawWith(t TB, s *server.CoreServer, seed []byte)
}
