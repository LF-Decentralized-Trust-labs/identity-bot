package drivers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type DriverStatus struct {
	Status      string `json:"status"`
	Driver      string `json:"driver"`
	Version     string `json:"version"`
	KeriLibrary string `json:"keri_library"`
	// KeriVersion and ScriptPath identify WHICH driver answered. An agent will
	// adopt a healthy driver started by something else, so without these an
	// edit to the driver looks like it took effect when the running code is
	// somebody else's — a silent no-op that reads as a failed change.
	KeriVersion string `json:"keri_version"`
	ScriptPath  string `json:"script_path"`
	// DriverProtocol is what the driver can be relied on to do.
	//
	// Zero means a driver old enough not to report one, which is exactly the
	// case worth catching: such a driver silently discards anchors it does not
	// understand, so the event comes back well-formed and committing to
	// nothing. Comparing script paths cannot see that — the agent may be
	// running precisely the file it was configured with, and that file may
	// simply be older than the agent needs.
	DriverProtocol int    `json:"driver_protocol"`
	Uptime         string `json:"uptime"`
}

type DriverInceptionRequest struct {
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
	Name          string `json:"name,omitempty"`
	// Witnesses are designated in the inception event itself and are therefore
	// public. An identity with none is valid; it simply has nobody to detect
	// duplicity on its behalf, so a second conflicting version of its history
	// has nothing to contradict it.
	Witnesses []string `json:"witnesses,omitempty"`
	// Keys and NextKeys carry a full key set for an identity controlled by more
	// than one. Empty means the single PublicKey/NextPublicKey above, which is
	// every existing caller.
	Keys     []string `json:"keys,omitempty"`
	NextKeys []string `json:"next_keys,omitempty"`
	// Isith and Nsith are the signing thresholds — how many of those keys must
	// sign now, and how many of the next set must sign to rotate.
	//
	// Empty means the field is not sent. keripy defaults both to 1 and writes
	// kt:"1" either way, so sending "1" produces an identical event and an
	// identical identifier — checked, not assumed. These exist for the case that
	// genuinely differs: a threshold above one, over more than one key, which is
	// what a rotation to m-of-n needs.
	Isith string `json:"isith,omitempty"`
	Nsith string `json:"nsith,omitempty"`
	// Anchors are seals written into the event's own `a` field, and therefore
	// into what the identifier is derived from. An identity names its owner
	// here: a self-addressing identifier is the digest of this event, so
	// ownership cannot be added, removed or altered later without producing a
	// different identity.
	//
	// A person's agent does not use this. Its identity is delegated, so its
	// delegator is already named in the event.
	// Raw JSON, not maps. A seal's field order is part of it, and marshalling a
	// Go map sorts the keys — so a seal written {"i","s","d"} would leave here
	// as {"d","i","s"}, which another implementation refuses. Measured, not
	// assumed.
	Anchors []json.RawMessage `json:"anchors,omitempty"`
	// Toad is the threshold of accountable duplicity. Left at zero the driver
	// picks a simple majority, which is enough that a minority of unavailable
	// or dishonest witnesses can neither stall nor forge.
	Toad int `json:"toad,omitempty"`
}

type DriverInceptionResponse struct {
	AID            string                 `json:"aid"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	// RawBytesB64: base64 of the serialized inception event body.
	// The controller signs these bytes with its Ed25519 key, then calls /cesr-encode.
	RawBytesB64   string `json:"raw_bytes_b64"`
	PublicKey     string `json:"public_key"`
	NextKeyDigest string `json:"next_key_digest"`
}

type DriverHybridInceptionRequest struct {
	Synthetic bool   `json:"synthetic"`
	Name      string `json:"name,omitempty"`
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

type DriverDelegatedInceptionRequest struct {
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
	Name          string `json:"name"`
	DelegatorName string `json:"delegator_name"`
}

type DriverDelegatedInceptionResponse struct {
	AID           string                 `json:"aid"`
	DelegatorAID  string                 `json:"delegator_aid"`
	Said          string                 `json:"said"`
	DipEvent      map[string]interface{} `json:"dip_event"`
	DelegatorIxn  map[string]interface{} `json:"delegator_ixn,omitempty"`
	RawBytesB64   string                 `json:"raw_bytes_b64"`
	PublicKey     string                 `json:"public_key"`
	NextKeyDigest string                 `json:"next_key_digest"`
}

type DriverRotationRequest struct {
	Name             string        `json:"name"`
	NewPublicKey     string        `json:"new_public_key"`
	NewNextPublicKey string        `json:"new_next_public_key"`
	Data             []interface{} `json:"data,omitempty"`
	// Keys, NextKeys, Isith and Nsith change WHO CONTROLS the identity, not
	// merely which key it uses. This is how an identity controlled by one party
	// comes to be controlled by several: the key set grows and the threshold rises
	// in a single event, and the identifier does not change.
	//
	// It is also the only place a threshold can be introduced. Founding needs to
	// anticipate nothing — an identity created by one person is already
	// one-of-one — so the growth happens here or nowhere.
	Keys []string `json:"keys,omitempty"`
	// NextKeyDigests are DIGESTS of the successor keys, not the keys. What a
	// rotation commits to is the digest; publishing the successors themselves
	// would defeat pre-rotation entirely, since the point is that nobody knows
	// them until they are used.
	NextKeyDigests []string `json:"next_key_digests,omitempty"`
	Isith          string   `json:"isith,omitempty"`
	Nsith          string   `json:"nsith,omitempty"`
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
	// RawBytesB64: sign with the PRE-ROTATED key (mnemonic index 1), then /cesr-encode.
	RawBytesB64    string `json:"raw_bytes_b64"`
	SequenceNumber int    `json:"sequence_number"`
}

type DriverInteractRequest struct {
	Name string        `json:"name"`
	Data []interface{} `json:"data"`
}

type DriverInteractResponse struct {
	AID      string                 `json:"aid"`
	IxnEvent map[string]interface{} `json:"ixn_event"`
	// RawBytesB64: sign with the CURRENT signing key, then call /cesr-encode.
	RawBytesB64    string `json:"raw_bytes_b64"`
	Said           string `json:"said"`
	SequenceNumber int    `json:"sequence_number"`
}

// DriverReloadIdentityRequest seeds the driver's in-memory _identities dict from
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
}

type DriverReloadIdentityResponse struct {
	AID            string `json:"aid"`
	SequenceNumber int    `json:"sequence_number"`
	KelEvents      int    `json:"kel_events"`
	Status         string `json:"status"`
}

type DriverSignRequest struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type DriverSignResponse struct {
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

type DriverSignForNameRequest struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

type DriverSignForNameResponse struct {
	Sig string `json:"sig"`
	AID string `json:"aid"`
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
	RawEventsB64   []string `json:"raw_events_b64"`
	SequenceNumber int      `json:"sequence_number"`
	EventCount     int      `json:"event_count"`
}

type DriverVerifyRequest struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

type DriverVerifyResponse struct {
	Valid     bool   `json:"valid"`
	PublicKey string `json:"public_key"`
}

type DriverFormatCredentialRequest struct {
	Claims     map[string]interface{} `json:"claims"`
	SchemaSaid string                 `json:"schema_said"`
	IssuerAid  string                 `json:"issuer_aid"`
}

type DriverFormatCredentialResponse struct {
	RawBytesB64 string `json:"raw_bytes_b64"`
	Said        string `json:"said"`
	Size        int    `json:"size"`
}

type DriverResolveOobiRequest struct {
	URL string `json:"url"`
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
}

type DriverValidateKELRequest struct {
	AID    string                   `json:"aid"`
	Events []map[string]interface{} `json:"events"`
}

type DriverValidateKELResponse struct {
	KelVerified      bool     `json:"kel_verified"`
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

type DriverMultisigRequest struct {
	AIDs        []string `json:"aids"`
	Threshold   int      `json:"threshold"`
	CurrentKeys []string `json:"current_keys"`
	// NextKeys are what the identity commits to rotating to. Without them the
	// inception commits to no successor and the identity can never rotate —
	// which for an owned identity means a compromised signer can never be
	// replaced and ownership can never be transferred, since transferring is a
	// rotation.
	NextKeys  []string `json:"next_keys,omitempty"`
	EventType string   `json:"event_type"`
}

type DriverMultisigResponse struct {
	RawBytesB64 string `json:"raw_bytes_b64"`
	Said        string `json:"said"`
	Pre         string `json:"pre"`
	EventType   string `json:"event_type"`
	Size        int    `json:"size"`
}

type DriverIssueCredentialRequest struct {
	Name       string                 `json:"name"`
	Claims     map[string]interface{} `json:"claims"`
	SchemaSaid string                 `json:"schema_said"`
	HolderAid  string                 `json:"holder_aid"`
	// Edges: optional ACDC edge block entries for credential chaining.
	// Structure: {"<label>": {"n": "<parent-SAID>", "s": "<schema-SAID>"}}
	// The driver computes the edges block SAID and includes the 'e' field in the ACDC body.
	Edges map[string]interface{} `json:"edges,omitempty"`
	// RegistrySaid, when set, issues the credential into a TEL registry: the ACDC
	// carries an "ri" field and the KEL anchor is a TEL issuance (iss) seal, so the
	// credential can later be cryptographically revoked. Empty = legacy issuance.
	RegistrySaid string `json:"registry_said,omitempty"`
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
	// the driver all along and read by nobody, so the event was stored without
	// the only bytes its signature and its own digest can be checked against.
	IxnRawBytesB64 string `json:"ixn_raw_bytes_b64"`
}

// DriverRevokeCredentialResponse is the result of revoking a registry-backed credential.
type DriverRevokeCredentialResponse struct {
	RevSaid        string                 `json:"rev_said"`
	RevEvent       map[string]interface{} `json:"rev_event"`
	IxnSaid        string                 `json:"ixn_said"`
	IxnEvent       map[string]interface{} `json:"ixn_event"`
	SequenceNumber int                    `json:"sequence_number"`
	// IxnRawBytesB64 is the anchoring event as KERI serialised it. The driver
	// has always returned this; nothing read it, so the event was stored
	// without the only bytes its signature and its own digest can be checked
	// against.
	IxnRawBytesB64 string `json:"ixn_raw_bytes_b64"`
}

type DriverPresentCredentialRequest struct {
	AcdcSaid   string `json:"acdc_said"`
	HolderAid  string `json:"holder_aid"`
	IssuerAid  string `json:"issuer_aid,omitempty"`
	SchemaSaid string `json:"schema_said,omitempty"`
}

type DriverPresentCredentialResponse struct {
	PresentationSaid    string                 `json:"presentation_said"`
	PresentationJsonB64 string                 `json:"presentation_json_b64"`
	PresentationBody    map[string]interface{} `json:"presentation_body"`
	// PresSaidB64: base64 of pres_said.encode(); sign these bytes with holder's key.
	PresSaidB64 string `json:"pres_said_b64"`
}

type DriverSubmitReceiptRequest struct {
	EventSAID        string   `json:"event_said"`
	WitnessAID       string   `json:"witness_aid"`
	WitnessPublicKey string   `json:"witness_public_key"`
	CesrSignature    string   `json:"cesr_signature"`
	TrustedWitnesses []string `json:"trusted_witnesses,omitempty"`
	Threshold        int      `json:"threshold,omitempty"`
}

type DriverSubmitReceiptResponse struct {
	Accepted     bool     `json:"accepted"`
	ThresholdMet bool     `json:"threshold_met"`
	ReceiptCount int      `json:"receipt_count"`
	Errors       []string `json:"errors"`
}

type DriverKerlReceiptEntry struct {
	WitnessAID    string `json:"witness_aid"`
	CesrSignature string `json:"cesr_sig"`
}

type DriverGetKerlResponse struct {
	EventSAID    string                   `json:"event_said"`
	Receipts     []DriverKerlReceiptEntry `json:"receipts"`
	ReceiptCount int                      `json:"receipt_count"`
	ThresholdMet bool                     `json:"threshold_met"`
	Errors       []string                 `json:"errors"`
}

type DriverVerifyCredentialRequest struct {
	// AcdcJson: base64-encoded ACDC JSON string to verify (matches driver field acdc_json_b64).
	AcdcJson string `json:"acdc_json_b64"`
	// IssuerKelEvents: the issuer's KEL as raw KED dicts (driver field: issuer_kel).
	IssuerKelEvents []map[string]interface{} `json:"issuer_kel,omitempty"`
	// HolderAid: expected holder AID (subject of the credential).
	HolderAid string `json:"holder_aid,omitempty"`
	// PresentationSaid: base64 of pres_said.encode() — bytes the holder signed (driver field: pres_said_b64).
	PresentationSaid string `json:"pres_said_b64,omitempty"`
	// CesrSignature: the holder's CESR '0B...' signature over pres_said bytes (driver field: pres_cesr_sig).
	CesrSignature string `json:"pres_cesr_sig,omitempty"`
	// HolderPublicKey: the holder's current Ed25519 public key (base64).
	HolderPublicKey string `json:"holder_public_key,omitempty"`
	// TrustedSchemaSaids: list of accepted schema SAIDs; empty = accept all.
	TrustedSchemaSaids []string `json:"trusted_schema_saids,omitempty"`
}

type DriverVerifyCredentialResponse struct {
	Verified bool                   `json:"verified"`
	Checks   map[string]interface{} `json:"checks"`
	Errors   []string               `json:"errors"`
	AcdcSaid string                 `json:"acdc_said"`
}

type DriverCesrEncodeRequest struct {
	RawSigB64 string `json:"raw_sig_b64"`
}

type DriverCesrEncodeResponse struct {
	CesrSig string `json:"cesr_sig"`
	Length  int    `json:"length"`
}

type DriverErrorResponse struct {
	Error string `json:"error"`
}

type KeriDriver struct {
	BaseURL string
	client  *http.Client
	process *exec.Cmd
	managed bool
}

// resolveDriverScript decides which driver file this agent would start.
//
// Extracted so the adoption path can ask the same question. Adopting a driver
// somebody else started is fine; adopting one running DIFFERENT code without
// saying so is what turns an edit into a silent no-op.
func resolveDriverScript() string {
	if p := os.Getenv("KERI_DRIVER_SCRIPT"); p != "" {
		return p
	}
	// Next to the executable, which is how a packaged build is laid out.
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "drivers", "keri-core", "server.py")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	// Running from source: the drivers directory sits beside or one level above.
	for _, rel := range []string{
		"./drivers/keri-core/server.py",
		"../drivers/keri-core/server.py",
	} {
		if _, statErr := os.Stat(rel); statErr == nil {
			return rel
		}
	}
	return "./drivers/keri-core/server.py" // last resort, keeps the old behaviour
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown — this driver predates reporting it"
	}
	return s
}

func NewKeriDriver() *KeriDriver {
	port := os.Getenv("KERI_DRIVER_PORT")
	if port == "" {
		port = "9999"
	}

	return &KeriDriver{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%s", port),
		client:  &http.Client{Timeout: 30 * time.Second},
		managed: true,
	}
}

// NewKeriDriverAt returns a driver that talks to an already-running driver at
// baseURL and never starts or stops one.
//
// The zero KeriDriver is not usable — its HTTP client is nil, so the first
// request panics rather than failing — which meant the only way to exercise a
// caller was against a real Python driver. That is a heavy dependency for
// testing what a caller does with a response, and it is why the request-shaping
// code below went unexercised.
func NewKeriDriverAt(baseURL string) *KeriDriver {
	return &KeriDriver{
		BaseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
		managed: false,
	}
}

// requiredDriverProtocol is the driver contract this agent depends on.
//
// Raise it alongside the driver whenever the agent starts relying on something
// new, so that an old driver is refused at startup rather than discovered later
// from the shape of what it returned.
//
// 1: anchors written into inception events; witness receipts counted during
//
//	key-log validation; events verified against canonical bytes.
const requiredDriverProtocol = 1

// checkDriverProtocol refuses a driver that cannot do what this agent will ask.
func checkDriverProtocol(status *DriverStatus) error {
	if status == nil {
		return fmt.Errorf("the KERI driver did not say what it is")
	}
	if status.DriverProtocol < requiredDriverProtocol {
		return fmt.Errorf(
			"the KERI driver at %s speaks contract %d and this agent needs %d — "+
				"an older driver silently ignores what it does not understand, so an "+
				"identity founded against it would commit to nothing and look correct",
			orUnknown(status.ScriptPath), status.DriverProtocol, requiredDriverProtocol)
	}
	return nil
}

func (d *KeriDriver) Start() error {
	log.Printf("[keri-driver] Starting managed Python KERI driver...")

	driverPort := os.Getenv("KERI_DRIVER_PORT")
	if driverPort == "" {
		driverPort = "9999"
	}

	// External-driver mode: the KERI driver is supervised as its own process
	// (a separate launchd/systemd service, or a sidecar container) and this
	// backend only adopts it — never spawns a child. This is the robust
	// deployment model: the driver's lifecycle is decoupled from the backend's,
	// so a backend restart can't orphan a driver or contend for the keystore,
	// and the driver runs directly under the supervisor rather than as a
	// grandchild. Wait up to the ready timeout for it (the supervisor may still
	// be bringing it up), then adopt; if it never appears, fail so the
	// supervisor retries the backend (no child driver is ever spawned here).
	if isTruthy(os.Getenv("KERI_DRIVER_EXTERNAL")) {
		log.Printf("[keri-driver] External driver mode: adopting supervised driver on %s (never spawning a child)", d.BaseURL)
		d.managed = false
		deadline := time.Now().Add(driverReadyTimeout())
		for time.Now().Before(deadline) {
			if status, err := d.GetStatus(); err == nil && status.Status == "active" {
				if perr := checkDriverProtocol(status); perr != nil {
					return perr
				}
				log.Printf("[keri-driver] Adopted external driver (library: %s, contract %d)",
					status.KeriLibrary, status.DriverProtocol)
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("external KERI driver not reachable on %s within %s", d.BaseURL, driverReadyTimeout())
	}

	// Self-healing startup. Two hazards make a naive spawn crash-loop under a
	// process supervisor (launchd/systemd KeepAlive):
	//  1. A previous backend that exited on a fatal error orphaned its child
	//     driver, which still holds the port and an open lock on the KERI
	//     keystore (LMDB). A fresh driver then contends for that lock and never
	//     becomes ready — the failure re-triggers the supervisor, sustaining a
	//     restart spiral.
	//  2. A healthy driver from a prior/parallel instance is already serving.
	// Adopt a healthy one; reclaim the port from a wedged one. Either way a
	// single, uncontended driver ends up owning the keystore.
	if status, err := d.GetStatus(); err == nil && status.Status == "active" {
		log.Printf("[keri-driver] Adopting already-running healthy driver on %s (library: %s %s, script: %s)",
			d.BaseURL, status.KeriLibrary, status.KeriVersion, orUnknown(status.ScriptPath))

		// Say so loudly when the adopted driver is running a different file
		// than this agent was configured with. Adopting avoids duplicate
		// processes, which is worth having; adopting SILENTLY means a developer
		// edits the driver, restarts, and measures the old code without any
		// signal that their change never loaded.
		if configured := resolveDriverScript(); status.ScriptPath != "" && configured != "" {
			if want, err := filepath.Abs(configured); err == nil && want != status.ScriptPath {
				log.Printf("[keri-driver] WARNING: the adopted driver is running %s, not the configured %s — "+
					"changes to the configured script are NOT in effect",
					status.ScriptPath, want)
			}
		}
		if perr := checkDriverProtocol(status); perr != nil {
			return perr
		}
		d.managed = false
		return nil
	}
	reclaimDriverPort(driverPort)

	scriptPath := resolveDriverScript()

	pythonBin := os.Getenv("KERI_DRIVER_PYTHON")
	if pythonBin == "" {
		pythonBin = "python3"
	}

	port := driverPort

	cmd := exec.Command(pythonBin, scriptPath)

	env := append(os.Environ(),
		fmt.Sprintf("KERI_DRIVER_PORT=%s", port),
		"KERI_DRIVER_HOST=127.0.0.1",
	)

	// On Windows, pysodium uses ctypes.util.find_library which searches PATH.
	// Prepend the keri-driver directory so libsodium.dll is found at startup.
	if runtime.GOOS == "windows" {
		driverDir := filepath.Dir(scriptPath)
		if abs, err := filepath.Abs(driverDir); err == nil {
			driverDir = abs
		}
		pathKey := "PATH"
		for i, e := range env {
			if len(e) >= 5 && e[:5] == "PATH=" {
				env[i] = pathKey + "=" + driverDir + ";" + e[5:]
				pathKey = ""
				break
			}
		}
		if pathKey != "" {
			env = append(env, "PATH="+driverDir)
		}
		log.Printf("[keri-driver] Prepended keri-driver dir to PATH for libsodium: %s", driverDir)
	}

	// On macOS/Linux, pysodium loads libsodium via ctypes.util.find_library('sodium'),
	// which macOS resolves through DYLD_FALLBACK_LIBRARY_PATH (Linux via LD_LIBRARY_PATH).
	// The self-contained app bundles libsodium in <backend>/lib (scriptPath is
	// <backend>/keri-driver/server.py). Point the driver there so KERI crypto works
	// without a system libsodium. The bundled Python is signed with the
	// allow-dyld-environment-variables entitlement so this survives the hardened runtime.
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		backendDir := filepath.Dir(filepath.Dir(scriptPath)) // <backend>
		libDir := filepath.Join(backendDir, "lib")
		if abs, err := filepath.Abs(libDir); err == nil {
			libDir = abs
		}
		if fi, err := os.Stat(libDir); err == nil && fi.IsDir() {
			key := "DYLD_FALLBACK_LIBRARY_PATH="
			if runtime.GOOS == "linux" {
				key = "LD_LIBRARY_PATH="
			}
			n := len(key)
			merged := false
			for i, e := range env {
				if len(e) >= n && e[:n] == key {
					env[i] = key + libDir + string(os.PathListSeparator) + e[n:]
					merged = true
					break
				}
			}
			if !merged {
				env = append(env, key+libDir)
			}
			log.Printf("[keri-driver] Added bundled lib dir for libsodium: %s", libDir)
		}
	}

	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start KERI driver: %w", err)
	}

	d.process = cmd
	log.Printf("[keri-driver] Python process started (PID: %d)", cmd.Process.Pid)

	return d.waitForReady(driverReadyTimeout())
}

// isTruthy reports whether an env value means "on".
func isTruthy(v string) bool {
	switch v {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	}
	return false
}

// driverReadyTimeout is how long Start waits for the driver's /status to report
// active. Override with KERI_DRIVER_READY_TIMEOUT (seconds) for slow cold starts
// (e.g. first keystore init on constrained hardware). A clean start is ~1s.
func driverReadyTimeout() time.Duration {
	if v := os.Getenv("KERI_DRIVER_READY_TIMEOUT"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 30 * time.Second
}

// reclaimDriverPort best-effort kills any process holding the driver port. It
// runs only when no healthy driver answered (Start already adopted a healthy
// one), so the holder is a wedged/orphaned driver blocking a clean restart.
// Best-effort by design: failures are logged, never fatal.
func reclaimDriverPort(port string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Find the PID owning the port, then kill it.
		cmd = exec.Command("cmd", "/C",
			fmt.Sprintf(`for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%s ^| findstr LISTENING') do taskkill /F /PID %%a`, port))
	default: // darwin, linux
		cmd = exec.Command("sh", "-c", fmt.Sprintf("lsof -ti tcp:%s | xargs -r kill -9", port))
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		// A non-zero exit usually just means nothing was listening — expected.
		log.Printf("[keri-driver] port %s reclaim (no stale holder or already free): %v %s", port, err, string(out))
	} else if len(out) > 0 {
		log.Printf("[keri-driver] reclaimed port %s from a stale holder: %s", port, string(out))
	}
}

func (d *KeriDriver) waitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		status, err := d.GetStatus()
		if err == nil && status.Status == "active" {
			log.Printf("[keri-driver] Driver ready (attempt %d) — library: %s", attempt, status.KeriLibrary)
			return nil
		}

		if attempt <= 3 {
			time.Sleep(500 * time.Millisecond)
		} else {
			time.Sleep(1 * time.Second)
		}
	}

	return fmt.Errorf("KERI driver did not become ready within %s", timeout)
}

func (d *KeriDriver) Stop() {
	if d.process != nil && d.process.Process != nil {
		log.Printf("[keri-driver] Stopping Python KERI driver (PID: %d)...", d.process.Process.Pid)
		d.process.Process.Kill()
		d.process.Wait()
		log.Printf("[keri-driver] KERI driver stopped")
	}
}

func (d *KeriDriver) GetStatus() (*DriverStatus, error) {
	resp, err := d.client.Get(d.BaseURL + "/status")
	if err != nil {
		return nil, fmt.Errorf("driver status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("driver status returned %d", resp.StatusCode)
	}

	var status DriverStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode driver status: %w", err)
	}

	return &status, nil
}

// Incept founds an identity, optionally designating witnesses for it.
func (d *KeriDriver) Incept(req InceptionRequest) (*DriverInceptionResponse, error) {
	body := DriverInceptionRequest{
		PublicKey:     req.PublicKey,
		NextPublicKey: req.NextPublicKey,
		Name:          req.Name,
		Witnesses:     req.Witnesses,
		Toad:          req.Toad,
	}
	if req.OwnerAID != "" {
		seal, err := ownerEventSeal(req.OwnerAID)
		if err != nil {
			return nil, err
		}
		body.Anchors = append(body.Anchors, seal)
	}
	for _, a := range req.AnchorData {
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("an anchor cannot be encoded: %w", err)
		}
		body.Anchors = append(body.Anchors, raw)
	}
	return d.postInceptionRequest(body)
}

func (d *KeriDriver) CreateInception(publicKey, nextPublicKey string) (*DriverInceptionResponse, error) {
	return d.postInception(publicKey, nextPublicKey, "", nil)
}

// CreateOwnedInception creates an identity that names its owner in the event
// that creates it.
//
// This is how an identity that answers to somebody else comes into being. Some
// party brought it into existence and answers for it, and that fact has to be
// true in a way anyone can check. Putting it in the inception event rather than
// in a record beside the database means it cannot be rewritten by whoever can
// write the file, and can be read by anybody who can read the log.
//
// The owner is a per-relationship identifier rather than a delegator, on
// purpose. A delegation cannot be transferred, only destroyed, so a delegated
// identity could never be handed on without killing it and every relationship
// it ever had. Anchored, ownership changes by rotation and the identity
// outlives the arrangement it was created under.
func (d *KeriDriver) CreateOwnedInception(publicKey, nextPublicKey, name, ownerAID string) (*DriverInceptionResponse, error) {
	if ownerAID == "" {
		// Refused rather than defaulted. An identity with no owner answers to
		// nobody, and the whole point of this path is that there is no such
		// moment to fall into.
		return nil, fmt.Errorf("an owned identity must name its owner in its inception event")
	}
	// No threshold is declared here, and that was worth checking rather than
	// assuming.
	//
	// An identity founded by one party IS one-of-one, but keripy already writes
	// kt:"1" whether a threshold is passed or not — the event, and therefore the
	// identifier, is byte-identical either way. Passing "1"
	// explicitly would be a parameter that reads as meaningful and changes
	// nothing, which is worse than its absence.
	//
	// It also does not gate growth. An identity founded this way rotates to
	// two-of-two, or two-of-three, exactly as one that declared a threshold
	// would: verified against keripy 1.1.17 rather than reasoned about. So there
	// is nothing to get right at founding for the sake of later — the work is
	// entirely in the rotation.
	// An event seal naming the owner's inception. Every identity here is
	// self-addressing, so the identifier IS that event's digest and the seal
	// resolves to a real event.
	//
	// This used to be {"i": ownerAID, "r": "owner"}, which is not a shape KERI
	// defines. A strict reader parses this field as one of a closed set of
	// seals, and an independent implementation could not parse an inception
	// carrying the old form at all — so an owned identity's whole log was
	// unreadable to anything outside this project.
	seal, err := ownerEventSeal(ownerAID)
	if err != nil {
		return nil, err
	}
	return d.postInception(publicKey, nextPublicKey, name, []json.RawMessage{
		seal,
	})
}

// CreateInceptionAnchored founds an identity that carries extra seals in the
// event it is derived from.
//
// Both kinds of seal go in the same list, so they cannot be passed separately:
// an identity may name an owner and commit to its encryption keys, and the
// caller builds whichever of those apply. Passing an owner AID adds the owner
// seal; passing none omits it, which is the unowned case rather than an error
// here — the handler decides whether an owner is required.
func (d *KeriDriver) CreateInceptionAnchored(publicKey, nextPublicKey, name, ownerAID string,
	extra []map[string]interface{}) (*DriverInceptionResponse, error) {
	// Anchors travel as ordered JSON, not as maps. A seal's field order is part
	// of it, and marshalling a map sorts the keys — so a seal written
	// {"i","s","d"} would arrive as {"d","i","s"}, which a strict reader
	// refuses. Measured against an independent implementation, not assumed.
	var ordered []json.RawMessage
	if ownerAID != "" {
		seal, err := ownerEventSeal(ownerAID)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, seal)
	}
	for _, a := range extra {
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("an anchor cannot be encoded: %w", err)
		}
		ordered = append(ordered, raw)
	}
	if len(ordered) == 0 {
		ordered = nil
	}
	return d.postInception(publicKey, nextPublicKey, name, ordered)
}

func (d *KeriDriver) CreateHybridInception(synthetic bool, name string) (*DriverHybridInceptionResponse, error) {
	reqBody := DriverHybridInceptionRequest{Synthetic: synthetic, Name: name}
	body, err := d.doPost("/hybrid-inception", reqBody, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var result DriverHybridInceptionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode hybrid-inception response: %w", err)
	}
	return &result, nil
}

func (d *KeriDriver) CreateInceptionNamed(publicKey, nextPublicKey, name string) (*DriverInceptionResponse, error) {
	return d.postInception(publicKey, nextPublicKey, name, nil)
}

func (d *KeriDriver) CreateDelegatedInception(publicKey, nextPublicKey, name, delegatorName string) (*DriverDelegatedInceptionResponse, error) {
	reqBody := DriverDelegatedInceptionRequest{
		PublicKey:     publicKey,
		NextPublicKey: nextPublicKey,
		Name:          name,
		DelegatorName: delegatorName,
	}
	body, err := d.doPost("/delegated-inception", reqBody, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var result DriverDelegatedInceptionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode delegated-inception response: %w", err)
	}
	return &result, nil
}

func (d *KeriDriver) postInception(publicKey, nextPublicKey, name string,
	anchors []json.RawMessage) (*DriverInceptionResponse, error) {
	return d.postInceptionRequest(DriverInceptionRequest{
		PublicKey:     publicKey,
		NextPublicKey: nextPublicKey,
		Name:          name,
		Anchors:       anchors,
	})
}

// postInceptionRequest is the whole-request form, for callers that need a
// threshold or a key set. Kept separate from postInception so the ordinary
// single-key path cannot accidentally acquire either.
func (d *KeriDriver) postInceptionRequest(reqBody DriverInceptionRequest) (*DriverInceptionResponse, error) {

	body, err := d.doPost("/inception", reqBody, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	var result DriverInceptionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode inception response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) RotateAid(name, newPublicKey, newNextPublicKey string) (*DriverRotationResponse, error) {
	return d.RotateAidWithAnchor(name, newPublicKey, newNextPublicKey, nil)
}

// RotateToMultisig changes who controls an identity: a new key set and a new
// threshold, in one event, keeping the identifier.
//
// This is how an identity created by one party comes to be controlled by
// several. The keys are the OWNERS' — each generated on that owner's own
// device, with only the public half ever crossing the wire — so what this sends
// is a set of public keys and a number, never key material.
//
// anchorData rides along because the same event is where the owner seals go:
// the set of owners and the keys that enforce it change together, which is the
// only way they cannot disagree.
func (d *KeriDriver) RotateToMultisig(name string, keys, nextKeyDigests []string,
	isith, nsith string, anchorData []interface{}) (*DriverRotationResponse, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("a rotation must name the keys that will control the identity")
	}
	if len(nextKeyDigests) == 0 {
		// An identity that commits to no next keys cannot rotate again. That is
		// a one-way door and never what somebody adding an owner intended.
		return nil, fmt.Errorf(
			"a rotation must commit to next keys, or the identity can never rotate again")
	}
	if isith == "" {
		return nil, fmt.Errorf("a rotation that changes the key set must say how many must sign")
	}

	return d.postRotation(DriverRotationRequest{
		Name:           name,
		Keys:           keys,
		NextKeyDigests: nextKeyDigests,
		Isith:          isith,
		Nsith:          nsith,
		Data:           anchorData,
		// The single-key fields stay empty. The driver falls back to them only
		// when no set is given, and giving both would leave two answers to the
		// same question.
	})
}

func (d *KeriDriver) RotateAidWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*DriverRotationResponse, error) {
	return d.postRotation(DriverRotationRequest{
		Name:             name,
		NewPublicKey:     newPublicKey,
		NewNextPublicKey: newNextPublicKey,
		Data:             anchorData,
	})
}

func (d *KeriDriver) postRotation(reqBody DriverRotationRequest) (*DriverRotationResponse, error) {
	body, err := d.doPost("/rotation", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverRotationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode rotation response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) SignPayload(name, dataB64 string) (*DriverSignResponse, error) {
	reqBody := DriverSignRequest{
		Name: name,
		Data: dataB64,
	}

	body, err := d.doPost("/sign", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverSignResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode sign response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) SignForName(name, body string) (*DriverSignForNameResponse, error) {
	reqBody := DriverSignForNameRequest{
		Name: name,
		Body: body,
	}
	respBody, err := d.doPost("/sign-for-name", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var result DriverSignForNameResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode sign-for-name response: %w", err)
	}
	return &result, nil
}

func (d *KeriDriver) GetKel(name string) (*DriverKelResponse, error) {
	resp, err := d.client.Get(fmt.Sprintf("%s/kel?name=%s", d.BaseURL, url.QueryEscape(name)))
	if err != nil {
		return nil, fmt.Errorf("KEL request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read KEL response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, d.parseError(body, resp.StatusCode, "KEL request")
	}

	var result DriverKelResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode KEL response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) VerifySignature(dataB64, signature, publicKey string) (*DriverVerifyResponse, error) {
	reqBody := DriverVerifyRequest{
		Data:      dataB64,
		Signature: signature,
		PublicKey: publicKey,
	}

	body, err := d.doPost("/verify", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverVerifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode verify response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) Interact(name string, data []interface{}) (*DriverInteractResponse, error) {
	reqBody := DriverInteractRequest{Name: name, Data: data}

	body, err := d.doPost("/interact", reqBody, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	var result DriverInteractResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode interact response: %w", err)
	}

	return &result, nil
}

// ReloadIdentity seeds the driver's in-memory identity state from persisted DB data.
// Must be called after the driver is ready whenever an identity already exists in the store.
func (d *KeriDriver) ReloadIdentity(req *DriverReloadIdentityRequest) (*DriverReloadIdentityResponse, error) {
	body, err := d.doPost("/reload-identity", req, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("reload-identity failed: %w", err)
	}
	var result DriverReloadIdentityResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode reload-identity response: %w", err)
	}
	return &result, nil
}

func (d *KeriDriver) CesrEncode(rawSigB64 string) (*DriverCesrEncodeResponse, error) {
	reqBody := DriverCesrEncodeRequest{RawSigB64: rawSigB64}

	body, err := d.doPost("/cesr-encode", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverCesrEncodeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode cesr-encode response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) FormatCredential(claims map[string]interface{}, schemaSaid, issuerAid string) (*DriverFormatCredentialResponse, error) {
	reqBody := DriverFormatCredentialRequest{
		Claims:     claims,
		SchemaSaid: schemaSaid,
		IssuerAid:  issuerAid,
	}

	body, err := d.doPost("/format-credential", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverFormatCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode format-credential response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) ResolveOobi(url string) (*DriverResolveOobiResponse, error) {
	reqBody := DriverResolveOobiRequest{URL: url}

	body, err := d.doPost("/resolve-oobi", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverResolveOobiResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode resolve-oobi response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) PresentCredential(acdcSaid, holderAid, issuerAid, schemaSaid string) (*DriverPresentCredentialResponse, error) {
	reqBody := DriverPresentCredentialRequest{
		AcdcSaid:   acdcSaid,
		HolderAid:  holderAid,
		IssuerAid:  issuerAid,
		SchemaSaid: schemaSaid,
	}

	body, err := d.doPost("/credential/present", reqBody, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	var result DriverPresentCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode credential/present response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) IssueCredential(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}) (*DriverIssueCredentialResponse, error) {
	return d.IssueCredentialInRegistry(name, claims, schemaSaid, holderAid, edges, "")
}

// IssueCredentialInRegistry issues a credential, optionally into a TEL registry
// (registrySaid != ""), which makes it cryptographically revocable.
func (d *KeriDriver) IssueCredentialInRegistry(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*DriverIssueCredentialResponse, error) {
	reqBody := DriverIssueCredentialRequest{
		Name:         name,
		Claims:       claims,
		SchemaSaid:   schemaSaid,
		HolderAid:    holderAid,
		Edges:        edges,
		RegistrySaid: registrySaid,
	}

	body, err := d.doPost("/credential/issue", reqBody, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	var result DriverIssueCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode credential/issue response: %w", err)
	}

	return &result, nil
}

// InceptRegistry incepts a backerless credential registry (TEL) for the named
// issuer identity, anchored in its KEL.
func (d *KeriDriver) InceptRegistry(name string) (*DriverRegistryInceptResponse, error) {
	body, err := d.doPost("/registry/incept", map[string]string{"name": name}, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var result DriverRegistryInceptResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode registry/incept response: %w", err)
	}
	return &result, nil
}

// RevokeCredential emits a TEL revocation (rev) event for a registry-backed
// credential and anchors it in the issuer KEL. issSaid is the prior issuance event.
func (d *KeriDriver) RevokeCredential(name, acdcSaid, registrySaid, issSaid string) (*DriverRevokeCredentialResponse, error) {
	body, err := d.doPost("/credential/revoke", map[string]string{
		"name":          name,
		"acdc_said":     acdcSaid,
		"registry_said": registrySaid,
		"iss_said":      issSaid,
	}, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var result DriverRevokeCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode credential/revoke response: %w", err)
	}
	return &result, nil
}

func (d *KeriDriver) ValidateKEL(aid string, events []map[string]interface{}) (*DriverValidateKELResponse, error) {
	reqBody := DriverValidateKELRequest{AID: aid, Events: events}

	body, err := d.doPost("/validate-kel", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverValidateKELResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode validate-kel response: %w", err)
	}

	return &result, nil
}

// GenerateMultisigEvent builds a multi-signature event.
//
// nextKeys may be empty for event types that do not commit to successors, but
// an inception without them produces an identity that can never be rotated.
func (d *KeriDriver) GenerateMultisigEvent(aids []string, threshold int, currentKeys, nextKeys []string, eventType string) (*DriverMultisigResponse, error) {
	reqBody := DriverMultisigRequest{
		AIDs:        aids,
		Threshold:   threshold,
		CurrentKeys: currentKeys,
		NextKeys:    nextKeys,
		EventType:   eventType,
	}

	body, err := d.doPost("/generate-multisig-event", reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverMultisigResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode multisig event response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) SubmitReceipt(req *DriverSubmitReceiptRequest) (*DriverSubmitReceiptResponse, error) {
	body, err := d.doPost("/receipt/submit", req, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverSubmitReceiptResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode receipt/submit response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) GetKERL(eventSAID string, threshold int) (*DriverGetKerlResponse, error) {
	url := fmt.Sprintf("%s/receipt/kerl?event_said=%s&threshold=%d", d.BaseURL, eventSAID, threshold)
	resp, err := d.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("KERL request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read KERL response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, d.parseError(body, resp.StatusCode, "KERL request")
	}

	var result DriverGetKerlResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode KERL response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) VerifyCredential(req *DriverVerifyCredentialRequest) (*DriverVerifyCredentialResponse, error) {
	body, err := d.doPost("/credential/verify", req, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var result DriverVerifyCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode credential/verify response: %w", err)
	}

	return &result, nil
}

func (d *KeriDriver) doPost(path string, reqBody interface{}, expectedStatus int) ([]byte, error) {
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request for %s: %w", path, err)
	}

	resp, err := d.client.Post(
		d.BaseURL+path,
		"application/json",
		bytes.NewReader(bodyJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from %s: %w", path, err)
	}

	if resp.StatusCode != expectedStatus {
		return nil, d.parseError(body, resp.StatusCode, path)
	}

	return body, nil
}

func (d *KeriDriver) parseError(body []byte, statusCode int, operation string) error {
	var errResp DriverErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return fmt.Errorf("%s failed: %s", operation, errResp.Error)
	}
	return fmt.Errorf("%s failed with status %d: %s", operation, statusCode, string(body))
}

// ── Endpoint records ─────────────────────────────────────────────────────────
//
// An OOBI is a URL, and a URL handed to somebody outlives the infrastructure it
// points at. When a relay is left or an allocation expires, every counterparty
// holding that string is stranded — the relationship breaks because of an
// infrastructure change neither party made.
//
// The fix is that the controller signs where it currently is, and witnesses
// carry the record. A counterparty that cannot reach the address it has already
// holds the KEL, and the KEL names the witnesses, so it can ask them instead.
// Witnesses become the stable anchor and relay addresses become disposable,
// which is what lets an identity move between providers, or use several at
// once, without a migration.

// DriverEndpointRoleRequest authorizes or revokes an endpoint provider.
type DriverEndpointRoleRequest struct {
	CID   string `json:"cid"`
	EID   string `json:"eid"`
	Role  string `json:"role"`
	Allow bool   `json:"allow"`
}

// DriverEndpointLocationRequest states where a provider is reachable. An empty
// URL nullifies the location, which is how an identity says "not here any more"
// rather than leaving a dead address published.
type DriverEndpointLocationRequest struct {
	EID    string `json:"eid"`
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
}

// DriverEndpointResponse is an unsigned reply message. As everywhere else, the
// driver holds no keys: RawBytesB64 is signed here and returned through
// CesrEncode.
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

// EndpointRole builds a signed-reply body authorizing eid to act for cid in a
// role. Revoking is as important as granting: an endpoint that simply goes
// quiet is indistinguishable from one that is briefly down.
func (d *KeriDriver) EndpointRole(req *DriverEndpointRoleRequest) (*DriverEndpointResponse, error) {
	body, err := d.doPost("/endpoint/role", req, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("endpoint role: %w", err)
	}
	var result DriverEndpointResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode endpoint role response: %w", err)
	}
	return &result, nil
}

// EndpointLocation builds a signed-reply body stating the URL at which eid is
// currently reachable.
func (d *KeriDriver) EndpointLocation(req *DriverEndpointLocationRequest) (*DriverEndpointResponse, error) {
	if req.Scheme == "" {
		req.Scheme = "https"
	}
	body, err := d.doPost("/endpoint/location", req, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("endpoint location: %w", err)
	}
	var result DriverEndpointResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode endpoint location response: %w", err)
	}
	return &result, nil
}

// Rotate rotates the keys, and refuses to change the witness set.
//
// The Python driver's rotation endpoint takes a prefix, keys, a prior digest, a
// sequence number, next-key digests and anchor data — and nothing about
// witnesses. So a witness change cannot be expressed through it, and asking for
// one is refused rather than quietly dropped: an identity whose witnesses
// appeared to change but did not would keep collecting receipts from a witness
// it believed it had removed, and never collect any from the one it believed it
// had added.
//
// The in-process engine can do this. A deployment that needs to amend a witness
// set should be running it.
func (d *KeriDriver) Rotate(req RotationRequest) (*DriverRotationResponse, error) {
	if len(req.CutWitnesses) > 0 || len(req.AddWitnesses) > 0 || req.Toad > 0 {
		return nil, fmt.Errorf("this driver cannot change an identity's witnesses: its " +
			"rotation endpoint carries no witness fields, so the change would be silently " +
			"lost. Run the in-process engine for a deployment that amends witness sets")
	}
	return d.RotateAidWithAnchor(req.Name, req.NewPublicKey, req.NewNextPublicKey, req.AnchorData)
}
