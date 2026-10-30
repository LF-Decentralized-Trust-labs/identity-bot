// Package addon is the plug-in point for an add-on: the handle an add-on has
// on the Identity Agent core it is built into, beyond the server's exported
// API.
//
// An add-on is a Go package an app chooses to include alongside the core. It
// registers with server.RegisterAddon from its init, so importing it is what
// includes it, and it may live in any module: the core never imports one.
// What it gives the core is server.Addon; what it may ask of the server it
// runs on is exactly this package: Host, for one server, and Helpers, for
// what needs no server. Its tests build their worlds with addontest.
//
// The core's rules hold for every add-on, whoever wrote it. The add-ons are
// settled when server.New first runs, and none registers after. Every route
// an add-on mounts lies under a prefix it owns, which no core route and no
// other add-on's prefix can match, and a route mounted twice stops the
// server. When the core asks the add-ons who a caller is, an answer more than
// one gives is nobody's, and an error fails closed. An add-on's rules for a
// machine acting for the owner can only make a route harder to reach.
//
// This is a safeguard and not a security boundary. An add-on is code the
// app's maker chose to link into the same process, and such code can reach
// anything in that process. The server hands this handle only to a caller
// holding a token this module makes (internal/hostlink), so the handle is
// reached through this package and no other way by mistake, and a program
// that includes no add-on links none of it. Which code is trusted is decided
// by whoever builds the app, by choosing its add-ons.
//
// Every method calls the server's own: nothing here is a second copy.
package addon

import (
	"context"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/internal/hostlink"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"identity-agent-core/server"
	"identity-agent-core/store"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// The plain data the core and an add-on hand each other.
type (
	// Authority is who authorised a credential.
	Authority = coretypes.Authority
	// SignedRequest is a request exactly as it was signed, with its body.
	SignedRequest = coretypes.SignedRequest
	// Signer is one of the people who sign for this identity.
	Signer = coretypes.Signer
	// ControllerProof is a controller's signature over a request, as proof
	// of what the person behind it asked.
	ControllerProof = coretypes.ControllerProof
	// AgentRef is an AI agent an identity holds, as its asset names it.
	AgentRef = coretypes.AgentRef
	// GrantRef is a grant an identity issued, by its SAID.
	GrantRef = coretypes.GrantRef
	// OwnEvidence is what is kept with a message from one of this Identity
	// Agent's own AI agents, so its proof is checked again later from it
	// alone.
	OwnEvidence = coretypes.OwnEvidence
	// LogSignerRecord is which identity signs the governance log, and where
	// its signed chain begins.
	LogSignerRecord = coretypes.LogSignerRecord
)

// Of is the handle on s.
func Of(s *server.CoreServer) Host { return server.AddonHost(s, hostlink.New()).(Host) }

// Shared is the handle on what needs no server.
func Shared() Helpers { return server.AddonHost(nil, hostlink.New()).(Helpers) }

// Host is what an add-on may ask of the server it runs on.
type Host interface {
	// AddonState is what an add-on keeps for this server under key, made by
	// make the first time it is asked for. Keep a key of an unexported type
	// of the add-on's own, so no two add-ons share one.
	AddonState(key any, make func() any) any

	AnchorRecord() (bool, error)
	AssetHandler() *asset.Handler
	AuthorityOf(r *http.Request) (Authority, func(), error)
	AwaitingFor(holder string, pending bool) string
	BindSigner(aid string, signer string) (server.ControllerGrant, error)
	BuildRouter(flutterWebDir string) chi.Router
	CredentialLog(registrySAID string, acdcSAID string) ([]string, string, error)
	DelegatedFromHere(aid string, e OwnEvidence) error
	EngineSigns()
	EnrichProvenCaller(caller *permission.CallerContext)
	FindAgentAssetByAID(aid string) *AgentRef
	FindCapabilityGrant(aid string) *GrantRef
	GetPublicURL(r *http.Request) string
	GrantController(g server.ControllerGrant, now time.Time, by Authority) (server.ControllerGrant, error)
	GrantsHeldBy(agentAID string, usableOnly bool) []store.CredentialRecord
	HandleDIDCommInbound(w http.ResponseWriter, r *http.Request)
	HandleGrantController(w http.ResponseWriter, r *http.Request)
	HasBrowserSession(r *http.Request) bool
	HoldTheRecord() (string, bool, bool, func())
	InBackground(fn func(ctx context.Context))
	InitAssetHandler() error
	IsLiveBrowserSession(token string) bool
	IsVaultEntry(name string) bool
	IssueAssetCredential(kind *schemas.AssetGrant, holder string, issuer string, claims map[string]interface{}, expiry string, by Authority) (string, error)
	IssueCapabilityGrant(agent *asset.Asset, by Authority) (string, error)
	IssuedUnderFirstVersionTooLate(rec *store.CredentialRecord) bool
	KeyCanSign() error
	KeyIsElsewhere() bool
	KeySetFor(aid string) (*didcomm.KeySet, error)
	NoteRecorded()
	OwnAgentAtArrival(aid string, did *didcomm.DID) (string, error)
	OwnerAuthority() (*server.OwnerAuthority, error)
	PartyConversation(convID string, party string) string
	PersonStillStands(p Signer) bool
	ProvedSender(n store.Notification) (*didcomm.JWM, string, error)
	RecordDeliveryOnce(cc permission.CallerContext, messageID string, host string)
	RequireOwner(w http.ResponseWriter, r *http.Request) bool
	ResolveBearerToken(r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool)
	ResolveCaller(r *http.Request) permission.CallerContext
	// SignAsTheIdentity signs message with this Identity Agent's own
	// identity key, as login.SignString does, and returns the signature. The
	// key stays in the core.
	SignAsTheIdentity(message []byte) (string, error)
	RevokeController(aid string) error
	Router() chi.Router
	RowIsItsGrant(g server.ControllerGrant) error
	StoredKelForVerifying(aid string) ([]map[string]interface{}, error)
	TheOwner() (string, bool)
	ThePersonAsking(r *http.Request) (Signer, *ControllerProof, error)
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
	ReadInvocationSignerRecord(dataDir string) (LogSignerRecord, bool, error)
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
