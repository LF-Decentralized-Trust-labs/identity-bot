package drivers

// What the core needs from a KERI implementation.
//
// Until now it needed a *KeriDriver specifically — a handle on a Python process
// — and said so in fifty-four places. Two consequences followed from that, and
// both are the reason this interface exists.
//
// On desktop, nothing else could be substituted, so the Python runtime could
// never be removed however good the alternative got.
//
// On mobile the driver is not started at all, so every one of those fifty-four
// call sites takes its nil branch and answers "KERI driver not available". The
// Go core on a phone cannot perform a single KERI operation; the app routes them
// through Dart to a Rust library instead. That is not a gap anyone chose — it is
// what happens when the only implementation is a subprocess and the platform has
// no subprocesses.
//
// So the core depends on this interface, and an implementation backed by a Go
// KERI library satisfies it on every platform, including the one that has never
// been able to run a driver.
//
// The method set is deliberately the set the core CALLS, not everything the
// driver exposes. An interface that mirrored the driver would make the driver
// the specification, which is the arrangement being dismantled.
type KeriEngine interface {
	// Identity creation and key rotation.
	//
	// Incept is the full form and the only one that can designate witnesses.
	// The others are conveniences over it, kept because most callers want
	// neither witnesses nor an owner and should not have to say so.
	Incept(req InceptionRequest) (*DriverInceptionResponse, error)
	CreateInception(publicKey, nextPublicKey string) (*DriverInceptionResponse, error)
	CreateInceptionNamed(publicKey, nextPublicKey, name string) (*DriverInceptionResponse, error)
	CreateOwnedInception(publicKey, nextPublicKey, name, ownerAID string) (*DriverInceptionResponse, error)
	CreateDelegatedInception(publicKey, nextPublicKey, name, delegatorName string) (*DriverDelegatedInceptionResponse, error)
	RotateAid(name, newPublicKey, newNextPublicKey string) (*DriverRotationResponse, error)
	// RotateAidWithAnchor rotates and anchors data in the same event, so that
	// what the rotation records cannot be separated from the rotation itself.
	RotateAidWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*DriverRotationResponse, error)
	// Rotate is the full form, and the only one that can change who witnesses
	// an identity.
	//
	// A witness set is established at inception and can afterwards be amended
	// only by a rotation. Without this an identity can never drop a witness it
	// has stopped using, nor add one it has since found — its published witness
	// list is fixed for life while the agent's own view of who witnesses for it
	// drifts away from it.
	Rotate(req RotationRequest) (*DriverRotationResponse, error)
	// CreateHybridInception founds an identity holding both classical and
	// post-quantum keys.
	CreateHybridInception(synthetic bool, name string) (*DriverHybridInceptionResponse, error)
	// Thresholds are strings, not counts: KERI allows a weighted threshold
	// ("1/2", "1/3") as well as a plain one, and a signing policy that could
	// only be expressed as an integer would silently exclude the weighted case.
	RotateToMultisig(name string, keys, nextKeyDigests []string, isith, nsith string, anchorData []interface{}) (*DriverRotationResponse, error)
	GenerateMultisigEvent(aids []string, threshold int, currentKeys, nextKeys []string, eventType string) (*DriverMultisigResponse, error)

	// Anchoring and reading a key log.
	Interact(name string, data []interface{}) (*DriverInteractResponse, error)
	GetKel(name string) (*DriverKelResponse, error)
	ValidateKEL(aid string, events []map[string]interface{}) (*DriverValidateKELResponse, error)
	// ValidateKELBytes checks a log from the bytes it was published as.
	//
	// Preferred over ValidateKEL wherever the caller has them. Two checks are
	// impossible without canonical bytes — that the inception derives the
	// identifier, and that the events are signed — and those are the two that
	// distinguish a real log from a forged one. ValidateKEL remains for callers
	// that only ever had the parsed form.
	ValidateKELBytes(in ValidateKELInput) (*DriverValidateKELResponse, error)

	// Signing and verification.
	SignPayload(name, dataB64 string) (*DriverSignResponse, error)
	VerifySignature(dataB64, signature, publicKey string) (*DriverVerifyResponse, error)
	CesrEncode(rawSigB64 string) (*DriverCesrEncodeResponse, error)

	// Credentials and their transaction events.
	FormatCredential(claims map[string]interface{}, schemaSaid, issuerAid string) (*DriverFormatCredentialResponse, error)
	InceptRegistry(name string) (*DriverRegistryInceptResponse, error)
	IssueCredential(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}) (*DriverIssueCredentialResponse, error)
	IssueCredentialInRegistry(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*DriverIssueCredentialResponse, error)
	RevokeCredential(name, acdcSaid, registrySaid, issSaid string) (*DriverRevokeCredentialResponse, error)
	VerifyCredential(req *DriverVerifyCredentialRequest) (*DriverVerifyCredentialResponse, error)
	PresentCredential(acdcSaid, holderAid, issuerAid, schemaSaid string) (*DriverPresentCredentialResponse, error)

	// Witness receipts.
	SubmitReceipt(req *DriverSubmitReceiptRequest) (*DriverSubmitReceiptResponse, error)

	// Discovery. Not part of the event layer, and the one area a Go
	// implementation does not yet answer — see EngineCapabilities.
	ResolveOobi(url string) (*DriverResolveOobiResponse, error)
	EndpointLocation(req *DriverEndpointLocationRequest) (*DriverEndpointResponse, error)

	// Lifecycle and state.
	//
	// Meaningful for an implementation that is a separate process and trivial
	// for one that is a library. Kept on the interface so the core does not
	// have to know which it is holding.
	Start() error
	Stop()
	GetStatus() (*DriverStatus, error)
	ReloadIdentity(req *DriverReloadIdentityRequest) (*DriverReloadIdentityResponse, error)
}

// Ensure the Python driver satisfies the interface it was extracted from.
//
// If this stops compiling, the interface and the driver have diverged, which
// means a call site somewhere is about to lose an implementation without anyone
// noticing.
var _ KeriEngine = (*KeriDriver)(nil)

// InceptionRequest is everything an identity can be founded with.
//
// Witnesses matter here in a way they do not anywhere else: they are written
// into the inception event, so they are part of what the identifier IS. They
// cannot be added to an existing identity's founding afterwards, only amended
// by a later rotation — and an identity founded with none has no observer for
// the one event that establishes its keys.
type InceptionRequest struct {
	PublicKey     string
	NextPublicKey string
	// Name is what the engine files the identity under. Empty means the
	// identifier itself.
	Name string
	// OwnerAID names who this identity answers to, anchored in the event.
	OwnerAID string
	// AnchorData is written into the inception event alongside the owner seal.
	//
	// The identifier is a digest of the whole event, so anything anchored here
	// is part of what the identity IS and cannot be added or altered later. The
	// messaging keys go here for exactly that reason: a counterparty reads them
	// out of the identifier rather than asking the agent and believing it.
	AnchorData []map[string]interface{}
	// Witnesses are NON-TRANSFERABLE witness keys, not contact identifiers.
	// What the event names has to be the key its receipts verify against, or
	// checking one means resolving a key log first, forever.
	Witnesses []string
	// Toad is how many of those must receipt an event for it to be considered
	// witnessed. Zero lets the implementation derive a majority.
	Toad int
}

// RotationRequest is everything a rotation can change.
type RotationRequest struct {
	Name string
	// NewPublicKey must be the key the identity previously committed to.
	NewPublicKey     string
	NewNextPublicKey string
	// CutWitnesses and AddWitnesses amend the designated set.
	//
	// Given as changes rather than as a new list on purpose: an event carries
	// the cuts and adds themselves, so anyone reading the log sees what changed
	// rather than having to diff two sets and infer it. Both are
	// non-transferable witness keys, as at inception.
	CutWitnesses []string
	AddWitnesses []string
	// Toad is the threshold after the change. Zero derives a majority of
	// whatever the set becomes, which is what a caller almost always wants —
	// stating one is for the case where it should not simply follow the count.
	Toad int
	// AnchorData is recorded in the same event as the key change, so the two
	// cannot be separated by anyone relaying the log.
	AnchorData []interface{}
}
