package drivers

import "errors"

// Message types exchanged with a KERI engine.
//
// These are the shapes the engine returns and the few request shapes the core
// hands it. They were extracted from the engine implementation so the core can
// depend on the data, not on any one engine. The in-process engine (keri-go)
// fills them directly; see the KeriEngine interface in engine.go.

type DriverStatus struct {
	Status      string `json:"status"`
	Driver      string `json:"driver"`
	Version     string `json:"version"`
	KeriLibrary string `json:"keri_library"`
	// KeriVersion and ScriptPath identify which engine answered.
	KeriVersion string `json:"keri_version"`
	ScriptPath  string `json:"script_path"`
	// DriverProtocol is what the engine can be relied on to do. Zero means an
	// engine old enough not to report one.
	DriverProtocol int    `json:"driver_protocol"`
	Uptime         string `json:"uptime"`
}

type DriverInceptionResponse struct {
	AID            string                 `json:"aid"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	// RawBytesB64: base64 of the serialized inception event body.
	// The controller signs these bytes with its Ed25519 key, then calls /cesr-encode.
	RawBytesB64   string `json:"raw_bytes_b64"`
	PublicKey     string `json:"public_key"`
	NextKeyDigest string `json:"next_key_digest"`
	// Signatures are the founding's controller signatures where the engine's
	// installed signer holds its keys; empty where it is signed elsewhere.
	Signatures []string `json:"signatures,omitempty"`
}

type DriverHybridInceptionResponse struct {
	AID            string                 `json:"aid"`
	SAID           string                 `json:"said"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	RawBytesB64    string                 `json:"raw_bytes_b64"`
	CipherSuite    string                 `json:"cipher_suite"`
	PublicKey      string                 `json:"public_key"`
	NextKeyDigest  string                 `json:"next_key_digest"`
}

type DriverDelegatedInceptionResponse struct {
	AID          string                 `json:"aid"`
	DelegatorAID string                 `json:"delegator_aid"`
	Said         string                 `json:"said"`
	DipEvent     map[string]interface{} `json:"dip_event"`
	DelegatorIxn map[string]interface{} `json:"delegator_ixn,omitempty"`
	// DelegatorIxnRawBytesB64 is the delegator's approving event as KERI
	// serialised it: the bytes the delegator signs, and the only bytes its
	// signature and its own digest can be checked against.
	DelegatorIxnRawBytesB64 string `json:"delegator_ixn_raw_bytes_b64,omitempty"`
	RawBytesB64             string `json:"raw_bytes_b64"`
	PublicKey               string `json:"public_key"`
	NextKeyDigest           string `json:"next_key_digest"`
}

type DriverRotationResponse struct {
	AID              string `json:"aid"`
	NewPublicKey     string `json:"new_public_key"`
	NewNextKeyDigest string `json:"new_next_key_digest"`
	// Keys and NextKeyDigests are the whole set the identity is now controlled
	// by, and Isith/Nsith the thresholds over them. Reported back because after
	// a rotation to several keys, "the public key" is one of them and a caller
	// that stored only that would build its next rotation from a set of one.
	Keys           []string               `json:"keys,omitempty"`
	NextKeyDigests []string               `json:"next_key_digests,omitempty"`
	Isith          string                 `json:"isith,omitempty"`
	Nsith          string                 `json:"nsith,omitempty"`
	RotationEvent  map[string]interface{} `json:"rotation_event"`
	Said           string                 `json:"said"`
	// RawBytesB64: sign with the key being rotated to (the one the previous
	// establishment event committed to), then /cesr-encode.
	RawBytesB64    string `json:"raw_bytes_b64"`
	SequenceNumber int    `json:"sequence_number"`
	// Signatures are the controller signatures the event was added with.
	Signatures []string `json:"signatures,omitempty"`
}

type DriverInteractResponse struct {
	AID      string                 `json:"aid"`
	IxnEvent map[string]interface{} `json:"ixn_event"`
	// RawBytesB64: sign with the CURRENT signing key, then call /cesr-encode.
	RawBytesB64    string `json:"raw_bytes_b64"`
	Said           string `json:"said"`
	SequenceNumber int    `json:"sequence_number"`
}

// DriverReloadIdentityRequest seeds the engine's in-memory identity state from
// persisted DB state. Called on server startup when an identity already exists.
// No private key material is included — only public state needed for IXN/issuance.
type DriverReloadIdentityRequest struct {
	AID            string                   `json:"aid"`
	PublicKey      string                   `json:"public_key"`
	NextKeyDigest  string                   `json:"next_key_digest"`
	SequenceNumber int                      `json:"sequence_number"`
	LastSAID       string                   `json:"last_said"`
	KEL            []map[string]interface{} `json:"kel"`
	// RawEventsB64[i] is the canonical serialisation of KEL[i], where the
	// stored record has one.
	//
	// KEL alone is not enough to restore a log that can be verified: it is
	// marshalled from a map, so its field order is sorted rather than original,
	// and an event rebuilt from it hashes to a different digest than the one it
	// carries. An engine handed only that can continue the log but can never
	// check the history it was handed.
	//
	// Empty entries are expected for events stored before the canonical bytes
	// were kept.
	RawEventsB64 []string `json:"raw_events_b64,omitempty"`
	// Signatures[i] are the controller signatures stored with KEL[i], in any
	// form ReadControllerSignature reads. An event with none was added unsigned
	// by an earlier version: nothing more is added to the log until it is
	// signed, because a log with an unsigned event in it verifies for nobody.
	Signatures [][]string `json:"signatures,omitempty"`
}

type DriverReloadIdentityResponse struct {
	AID            string `json:"aid"`
	SequenceNumber int    `json:"sequence_number"`
	KelEvents      int    `json:"kel_events"`
	Status         string `json:"status"`
}

type DriverSignResponse struct {
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

type DriverKelResponse struct {
	AID string                   `json:"aid"`
	KEL []map[string]interface{} `json:"kel"`
	// RawEventsB64[i] is the canonical serialisation of KEL[i].
	//
	// The parsed form cannot be re-serialised by a caller: field order is part
	// of the event and the identifier is a digest over those exact bytes, so a
	// language that marshals a map in its own order produces something that
	// verifies as nothing. Anything checking signatures or recomputing
	// identifiers must use these bytes.
	RawEventsB64 []string `json:"raw_events_b64"`
	// Signatures[i] are the controller signatures over RawEventsB64[i], each
	// an indexed signature as KERI attaches it. Empty for an event this engine
	// holds without them: one added unsigned by an earlier version.
	Signatures     [][]string `json:"signatures,omitempty"`
	SequenceNumber int        `json:"sequence_number"`
	EventCount     int        `json:"event_count"`
}

type DriverVerifyResponse struct {
	Valid     bool   `json:"valid"`
	PublicKey string `json:"public_key"`
}

type DriverFormatCredentialResponse struct {
	RawBytesB64 string `json:"raw_bytes_b64"`
	Said        string `json:"said"`
	Size        int    `json:"size"`
}

type DriverResolveOobiResponse struct {
	Endpoints []string `json:"endpoints"`
	OobiURL   string   `json:"oobi_url"`
	CID       string   `json:"cid"`
	EID       string   `json:"eid"`
	Role      string   `json:"role"`
	// Phase 3: KEL validation fields returned when resolve-oobi fetches and validates the KEL.
	KEL              []map[string]interface{} `json:"kel,omitempty"`
	KelVerified      bool                     `json:"kel_verified"`
	CurrentPublicKey string                   `json:"current_public_key,omitempty"`
	EventsValidated  int                      `json:"events_validated"`
	ValidationErrors []string                 `json:"validation_errors,omitempty"`
	// RawEvents are the canonical bytes the log was validated from, for a
	// caller that must read an event itself (a delegated inception's
	// delegator, say) and has to read the bytes that were checked rather
	// than a second, unchecked copy.
	RawEvents [][]byte `json:"-"`
	// Witnessed reports that every event carried receipts from enough of the
	// witnesses designated for it, from the receipts the introduction served.
	// An identity that names no witnesses has nothing to meet and reads true;
	// a caller that needs witnessing checks NamesWitnesses as well.
	Witnessed bool `json:"witnessed"`
}

type DriverValidateKELResponse struct {
	// KelVerified means authorship was proven: every event was signed, and
	// signed by the key the log itself puts in force at that point.
	//
	// It is what every trust gate in this agent reads before letting a log
	// establish anything, so it answers the strict question. A log that is
	// internally consistent but carries no signatures is not verified — it is
	// an unauthenticated document that happens to be well formed, and treating
	// the two alike would let anyone hand over a log they wrote themselves.
	KelVerified bool `json:"kel_verified"`

	// LogSound means the log holds together as a log: the events parse, they
	// chain, and the inception derives the identifier.
	//
	// Separate from KelVerified because the two genuinely differ, and the case
	// where they differ is routine rather than exotic — a log fetched from a
	// stranger over an introduction usually arrives without controller
	// signatures. Reporting that as unverified is correct; reporting it as
	// malformed would be false, and would leave a caller unable to tell a
	// stranger's honest log from a corrupt one.
	LogSound bool `json:"log_sound"`

	// EventsUnsigned is how many events carried no signature, which is the
	// specific reason KelVerified and LogSound part company.
	EventsUnsigned int `json:"events_unsigned,omitempty"`

	CurrentPublicKey string   `json:"current_public_key"`
	EventsValidated  int      `json:"events_validated"`
	ValidationErrors []string `json:"validation_errors,omitempty"`

	// Whether anybody stood behind this log, reported separately from whether
	// it verifies.
	//
	// A log can be internally sound and correctly signed by its controller and
	// still be one of two conflicting histories — nothing inside a log can rule
	// that out, only the witnesses who declined to sign the other one. So a
	// caller about to rely on this being the ONLY history has to ask this
	// question too, and a caller merely reading an identity's current key does
	// not.
	Witnessed        bool                   `json:"witnessed"`
	Witnesses        []string               `json:"witnesses,omitempty"`
	WitnessThreshold int                    `json:"witness_threshold"`
	WitnessDetail    []DriverWitnessedEvent `json:"witness_detail,omitempty"`
}

// DriverWitnessedEvent is the witnessing position of one event in a log.
type DriverWitnessedEvent struct {
	SequenceNumber   int  `json:"sequence_number"`
	Witnesses        int  `json:"witnesses"`
	Threshold        int  `json:"threshold"`
	ReceiptsVerified int  `json:"receipts_verified"`
	Witnessed        bool `json:"witnessed"`
}

type DriverMultisigResponse struct {
	RawBytesB64 string `json:"raw_bytes_b64"`
	Said        string `json:"said"`
	Pre         string `json:"pre"`
	EventType   string `json:"event_type"`
	Size        int    `json:"size"`
}

type DriverIssueCredentialResponse struct {
	AID         string                 `json:"aid"`
	AcdcSaid    string                 `json:"acdc_said"`
	AcdcJsonB64 string                 `json:"acdc_json_b64"`
	AcdcBody    map[string]interface{} `json:"acdc_body"`
	// IxnRawBytesB64: sign with the CURRENT signing key then call /cesr-encode.
	IxnRawBytesB64 string                 `json:"ixn_raw_bytes_b64"`
	IxnSaid        string                 `json:"ixn_said"`
	IxnEvent       map[string]interface{} `json:"ixn_event"`
	SequenceNumber int                    `json:"sequence_number"`
	// IssSaid is the SAID of the TEL issuance (iss) event when the credential was
	// issued into a registry. Persist it — revocation needs it as the prior event.
	IssSaid string `json:"iss_said,omitempty"`
	// IssRawBytesB64 is that issuance event as it was serialised.
	//
	// A verifier decides whether a credential is still valid by reading its
	// transaction log, and a log can only be checked from the bytes each event
	// was published as: the events are self-addressing and chain by digest, so
	// a re-serialised copy derives a different identifier and chains to
	// nothing. Without these the log exists and cannot be handed to anybody.
	IssRawBytesB64 string `json:"iss_raw_bytes_b64,omitempty"`
}

// DriverRegistryInceptResponse is the result of incepting a credential registry (TEL).
type DriverRegistryInceptResponse struct {
	RegistrySaid   string                 `json:"registry_said"`
	VcpSaid        string                 `json:"vcp_said"`
	VcpEvent       map[string]interface{} `json:"vcp_event"`
	VcpJsonB64     string                 `json:"vcp_json_b64"`
	IxnSaid        string                 `json:"ixn_said"`
	IxnEvent       map[string]interface{} `json:"ixn_event"`
	SequenceNumber int                    `json:"sequence_number"`
	// IxnRawBytesB64 is the anchoring event as KERI serialised it. Returned by
	// the engine all along and read by nobody, so the event was stored without
	// the only bytes its signature and its own digest can be checked against.
	IxnRawBytesB64 string `json:"ixn_raw_bytes_b64"`
}

// TELCommit is a registry inception, issuance or revocation together with the
// key-log interaction that anchors it, offered for keeping before the engine
// counts either as made.
type TELCommit struct {
	// AID is the identity whose key log the interaction extends.
	AID string
	// SN is the interaction's sequence number.
	SN int
	// KELRaw and TELRaw are the two events as published.
	KELRaw []byte
	TELRaw []byte
	// Signature is the identity's signature over KELRaw, checked by the
	// engine against the identity's current key.
	Signature string
}

// PreparedIssuance is a credential issued into a registry, built but not yet
// appended: the credential, its issuance event, and the interaction in the
// issuer's key log that anchors it, which whoever holds the issuer's key
// signs. Prior and SN are where the interaction extends the key log; it can
// be appended only while that is still the tip.
type PreparedIssuance struct {
	Issuer   string `json:"issuer"`
	Registry string `json:"registry"`
	AcdcRaw  []byte `json:"acdc_raw"`
	AcdcSAID string `json:"acdc_said"`
	IssRaw   []byte `json:"iss_raw"`
	IssSAID  string `json:"iss_said"`
	IxnRaw   []byte `json:"ixn_raw"`
	IxnSAID  string `json:"ixn_said"`
	SN       int    `json:"sn"`
	Prior    string `json:"prior"`
}

// PreparedRegistry is a registry's inception, built but not yet appended,
// with the interaction in the issuer's key log that anchors it.
type PreparedRegistry struct {
	Issuer   string `json:"issuer"`
	Registry string `json:"registry"`
	VcpRaw   []byte `json:"vcp_raw"`
	VcpSAID  string `json:"vcp_said"`
	IxnRaw   []byte `json:"ixn_raw"`
	IxnSAID  string `json:"ixn_said"`
	SN       int    `json:"sn"`
	Prior    string `json:"prior"`
}

// PreparedRevocation is a credential's revocation, built but not yet appended,
// with the interaction in the issuer's key log that anchors it.
type PreparedRevocation struct {
	Issuer   string `json:"issuer"`
	Registry string `json:"registry"`
	AcdcSAID string `json:"acdc_said"`
	IssSAID  string `json:"iss_said"`
	RevRaw   []byte `json:"rev_raw"`
	RevSAID  string `json:"rev_said"`
	IxnRaw   []byte `json:"ixn_raw"`
	IxnSAID  string `json:"ixn_said"`
	SN       int    `json:"sn"`
	Prior    string `json:"prior"`
}

// PreparedRevoker is an engine that can build a revocation and append it
// later, exactly as built, so it can be signed elsewhere in between.
type PreparedRevoker interface {
	PrepareRevocation(name, acdcSaid, registrySaid string) (*PreparedRevocation, error)
	AppendPreparedRevocation(name string, p *PreparedRevocation) (*DriverRevokeCredentialResponse, error)
}

// ErrStalePreparation is a prepared issuance whose key log has moved on since
// it was built: its interaction no longer extends the tip.
var ErrStalePreparation = errors.New("the key log has moved on since this issuance was prepared")

// PreparedIssuer is an engine that can build an issuance and append it later,
// exactly as built, so it can be checked, or signed elsewhere, in between.
type PreparedIssuer interface {
	PrepareCredentialInRegistry(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*PreparedIssuance, error)
	AppendPreparedIssuance(name string, p *PreparedIssuance) (*DriverIssueCredentialResponse, error)
	PrepareRegistryInception(name string) (*PreparedRegistry, error)
	AppendPreparedRegistry(name string, p *PreparedRegistry) (*DriverRegistryInceptResponse, error)
}

// KELKeep is an event an engine is about to append to an identity's key log,
// offered to be kept first.
type KELKeep struct {
	// AID is the identity whose key log the event extends, SN its place there.
	AID string
	SN  int
	// Raw is the event as published.
	Raw []byte
	// Delegated is set for a delegated inception: the new identity's inception,
	// which Raw, the delegator's interaction, approves.
	Delegated []byte
	// Signature is the identity's signature over Raw, checked by the engine
	// against the identity's current key before the event is offered.
	Signature string
	// Signatures are every controller signature over Raw, indexed as KERI
	// attaches them. Signature is the first of them, for a store that keeps
	// one.
	Signatures []string
	// Supersedes, when above zero, is the sequence number from which this
	// event, a recovery rotation, supersedes interactions already in the log:
	// they are moved to the record of what was superseded, never deleted.
	Supersedes int
	// Earlier are signatures this engine obtained for events already in the
	// log that were held without them, by sequence number, to be kept with
	// this one.
	Earlier map[int][]string
}

// KELKeeper is an engine that offers an event to be kept before it appends it.
// The keep is the caller's, per call; a keep that fails leaves the engine as it
// was, so it never holds an event the store does not and the next event cannot
// chain to one that was never kept.
type KELKeeper interface {
	InteractKept(name string, data []interface{}, keep func(KELKeep) error) (*DriverInteractResponse, error)
	// CreateDelegatedInceptionKept makes a delegated identity naming witnesses,
	// when given, and how many must receipt each of its events.
	CreateDelegatedInceptionKept(publicKey, nextPublicKey, name, delegatorName string, witnesses []string, toad int, keep func(KELKeep) error) (*DriverDelegatedInceptionResponse, error)
	// WitnessConfig is the witnesses an identity names now and its threshold.
	WitnessConfig(name string) ([]string, int, error)
}

// TELCommitter is an engine that offers each registry event to be kept before
// it appends it, so the engine never holds an event the store does not. A
// commit that fails leaves the engine as it was.
type TELCommitter interface {
	SetTELCommit(func(TELCommit) error)
}

// DriverRevokeCredentialResponse is the result of revoking a registry-backed credential.
type DriverRevokeCredentialResponse struct {
	RevSaid        string                 `json:"rev_said"`
	RevEvent       map[string]interface{} `json:"rev_event"`
	IxnSaid        string                 `json:"ixn_said"`
	IxnEvent       map[string]interface{} `json:"ixn_event"`
	SequenceNumber int                    `json:"sequence_number"`
	// IxnRawBytesB64 is the anchoring event as KERI serialised it. The engine
	// has always returned this; nothing read it, so the event was stored
	// without the only bytes its signature and its own digest can be checked
	// against.
	IxnRawBytesB64 string `json:"ixn_raw_bytes_b64"`
	// RevRawBytesB64 is the revocation itself, as serialised.
	//
	// The event that has to reach a verifier for the revocation to have any
	// effect. A revoked credential looks exactly like a live one until someone
	// is handed this.
	RevRawBytesB64 string `json:"rev_raw_bytes_b64,omitempty"`
}

type DriverPresentCredentialResponse struct {
	PresentationSaid    string                 `json:"presentation_said"`
	PresentationJsonB64 string                 `json:"presentation_json_b64"`
	PresentationBody    map[string]interface{} `json:"presentation_body"`
	// PresSaidB64: base64 of pres_said.encode(); sign these bytes with holder's key.
	PresSaidB64 string `json:"pres_said_b64"`
}

type DriverSubmitReceiptResponse struct {
	Accepted     bool     `json:"accepted"`
	ThresholdMet bool     `json:"threshold_met"`
	ReceiptCount int      `json:"receipt_count"`
	Errors       []string `json:"errors"`
}

type DriverVerifyCredentialRequest struct {
	// AcdcJson: base64-encoded ACDC JSON string to verify (matches engine field acdc_json_b64).
	AcdcJson string `json:"acdc_json_b64"`
	// IssuerKelEvents: the issuer's KEL as raw KED dicts (field: issuer_kel).
	IssuerKelEvents []map[string]interface{} `json:"issuer_kel,omitempty"`
	// HolderAid: expected holder AID (subject of the credential).
	HolderAid string `json:"holder_aid,omitempty"`
	// PresentationSaid: base64 of pres_said.encode() — bytes the holder signed (field: pres_said_b64).
	PresentationSaid string `json:"pres_said_b64,omitempty"`
	// CesrSignature: the holder's CESR '0B...' signature over pres_said bytes (field: pres_cesr_sig).
	CesrSignature string `json:"pres_cesr_sig,omitempty"`
	// HolderPublicKey: the holder's current Ed25519 public key (base64).
	//
	// Asserted by whoever is presenting, so on its own it establishes nothing:
	// a presenter can generate a key, name it here, and sign with it. It is
	// only worth anything once HolderKelEvents shows it is the key the subject
	// identity actually has in force.
	HolderPublicKey string `json:"holder_public_key,omitempty"`

	// PresentationBody is the presentation the holder signed.
	//
	// Needed because the signature alone binds to nothing. Without the body a
	// verifier sees a signature over some bytes and has no way to tell whether
	// those bytes are a presentation of THIS credential by THIS subject, or a
	// presentation of something else entirely — or not a presentation at all.
	PresentationBody map[string]interface{} `json:"presentation_body,omitempty"`

	// HolderKelEvents is the subject's key log, which is what turns the
	// asserted holder key into an established one.
	HolderKelEvents []map[string]interface{} `json:"holder_kel,omitempty"`

	// RegistryEventsB64 is the credential's transaction log, in order, as the
	// bytes each event was published as.
	//
	// Where revocation lives. A credential carries no indication that it was
	// revoked — revocation is an event in this log — so a verifier that does
	// not read it cannot tell a live credential from a withdrawn one, and the
	// holder of a revoked credential has every reason not to mention it.
	RegistryEventsB64 []string `json:"registry_events_b64,omitempty"`

	// TrustedSchemaSaids: list of accepted schema SAIDs; empty = accept all.
	TrustedSchemaSaids []string `json:"trusted_schema_saids,omitempty"`
}

type DriverVerifyCredentialResponse struct {
	Verified bool                   `json:"verified"`
	Checks   map[string]interface{} `json:"checks"`
	Errors   []string               `json:"errors"`
	AcdcSaid string                 `json:"acdc_said"`
}

type DriverCesrEncodeResponse struct {
	CesrSig string `json:"cesr_sig"`
	Length  int    `json:"length"`
}

// DriverEndpointLocationRequest states where a provider is reachable. An empty
// URL nullifies the location, which is how an identity says "not here any more"
// rather than leaving a dead address published.
type DriverEndpointLocationRequest struct {
	EID    string `json:"eid"`
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
}

// DriverEndpointResponse is an unsigned reply message. The engine holds no
// keys: RawBytesB64 is signed by the caller and returned through CesrEncode.
type DriverEndpointResponse struct {
	CID         string                 `json:"cid,omitempty"`
	EID         string                 `json:"eid"`
	Role        string                 `json:"role,omitempty"`
	URL         string                 `json:"url,omitempty"`
	Scheme      string                 `json:"scheme,omitempty"`
	Route       string                 `json:"route"`
	RpyEvent    map[string]interface{} `json:"rpy_event"`
	RawBytesB64 string                 `json:"raw_bytes_b64"`
	SAID        string                 `json:"said"`
}

// KELHolder is an engine that can find a key history by identifier, not only
// by the name it is held under. A name can be reused or renamed; the
// identifier cannot.
type KELHolder interface {
	GetKelByAID(aid string) (*DriverKelResponse, error)
}
