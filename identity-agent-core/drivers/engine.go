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
	CreateInception(publicKey, nextPublicKey string) (*DriverInceptionResponse, error)
	CreateInceptionNamed(publicKey, nextPublicKey, name string) (*DriverInceptionResponse, error)
	CreateOwnedInception(publicKey, nextPublicKey, name, ownerAID string) (*DriverInceptionResponse, error)
	CreateDelegatedInception(publicKey, nextPublicKey, name, delegatorName string) (*DriverDelegatedInceptionResponse, error)
	RotateAid(name, newPublicKey, newNextPublicKey string) (*DriverRotationResponse, error)
	// RotateAidWithAnchor rotates and anchors data in the same event, so that
	// what the rotation records cannot be separated from the rotation itself.
	RotateAidWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*DriverRotationResponse, error)
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
