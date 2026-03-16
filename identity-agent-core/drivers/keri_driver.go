package drivers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type DriverStatus struct {
	Status      string `json:"status"`
	Driver      string `json:"driver"`
	Version     string `json:"version"`
	KeriLibrary string `json:"keri_library"`
	Uptime      string `json:"uptime"`
}

type DriverInceptionRequest struct {
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
	Name          string `json:"name,omitempty"`
}

type DriverInceptionResponse struct {
	AID            string                 `json:"aid"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	// RawBytesB64: base64 of the serialized inception event body.
	// The controller signs these bytes with its Ed25519 key, then calls /cesr-encode.
	RawBytesB64   string `json:"raw_bytes_b64"`
	PublicKey      string `json:"public_key"`
	NextKeyDigest  string `json:"next_key_digest"`
}

type DriverRotationRequest struct {
	Name             string `json:"name"`
	NewPublicKey     string `json:"new_public_key"`
	NewNextPublicKey string `json:"new_next_public_key"`
}

type DriverRotationResponse struct {
	AID              string                 `json:"aid"`
	NewPublicKey     string                 `json:"new_public_key"`
	NewNextKeyDigest string                 `json:"new_next_key_digest"`
	RotationEvent    map[string]interface{} `json:"rotation_event"`
	// RawBytesB64: sign with the PRE-ROTATED key (mnemonic index 1), then /cesr-encode.
	RawBytesB64    string `json:"raw_bytes_b64"`
	SequenceNumber   int                    `json:"sequence_number"`
}

type DriverInteractRequest struct {
	Name string        `json:"name"`
	Data []interface{} `json:"data"`
}

type DriverInteractResponse struct {
	AID            string                 `json:"aid"`
	IxnEvent       map[string]interface{} `json:"ixn_event"`
	// RawBytesB64: sign with the CURRENT signing key, then call /cesr-encode.
	RawBytesB64    string `json:"raw_bytes_b64"`
	Said           string `json:"said"`
	SequenceNumber int    `json:"sequence_number"`
}

type DriverSignRequest struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type DriverSignResponse struct {
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

type DriverKelResponse struct {
	AID            string                   `json:"aid"`
	KEL            []map[string]interface{} `json:"kel"`
	SequenceNumber int                      `json:"sequence_number"`
	EventCount     int                      `json:"event_count"`
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
	Endpoints        []string                 `json:"endpoints"`
	OobiURL          string                   `json:"oobi_url"`
	CID              string                   `json:"cid"`
	EID              string                   `json:"eid"`
	Role             string                   `json:"role"`
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
}

type DriverMultisigRequest struct {
	AIDs        []string `json:"aids"`
	Threshold   int      `json:"threshold"`
	CurrentKeys []string `json:"current_keys"`
	EventType   string   `json:"event_type"`
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
}

type DriverIssueCredentialResponse struct {
	AID            string                 `json:"aid"`
	AcdcSaid       string                 `json:"acdc_said"`
	AcdcJsonB64    string                 `json:"acdc_json_b64"`
	AcdcBody       map[string]interface{} `json:"acdc_body"`
	// IxnRawBytesB64: sign with the CURRENT signing key then call /cesr-encode.
	IxnRawBytesB64 string                 `json:"ixn_raw_bytes_b64"`
	IxnSaid        string                 `json:"ixn_said"`
	IxnEvent       map[string]interface{} `json:"ixn_event"`
	SequenceNumber int                    `json:"sequence_number"`
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
	PresSaidB64         string                 `json:"pres_said_b64"`
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
	// AcdcJson: full ACDC JSON string to verify.
	AcdcJson string `json:"acdc_json"`
	// IssuerKelEvents: the issuer's KEL events as stored in contact_kels (may be nil/empty).
	IssuerKelEvents []map[string]interface{} `json:"issuer_kel_events,omitempty"`
	// HolderAid: expected holder AID (subject of the credential).
	HolderAid string `json:"holder_aid,omitempty"`
	// PresentationSaid: the SAID of the presentation being verified.
	PresentationSaid string `json:"presentation_said,omitempty"`
	// CesrSignature: the holder's CESR signature over pres_said.encode().
	CesrSignature string `json:"cesr_signature,omitempty"`
	// HolderPublicKey: the holder's current Ed25519 public key (base64).
	HolderPublicKey string `json:"holder_public_key,omitempty"`
	// TrustedSchemaSaids: list of accepted schema SAIDs; empty = accept all.
	TrustedSchemaSaids []string `json:"trusted_schema_saids,omitempty"`
}

type DriverVerifyCredentialResponse struct {
	Verified  bool                   `json:"verified"`
	Checks    map[string]interface{} `json:"checks"`
	Errors    []string               `json:"errors"`
	AcdcSaid  string                 `json:"acdc_said"`
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

func (d *KeriDriver) Start() error {
	log.Printf("[keri-driver] Starting managed Python KERI driver...")

	scriptPath := os.Getenv("KERI_DRIVER_SCRIPT")
	if scriptPath == "" {
		scriptPath = "./drivers/keri-core/server.py"
	}

	pythonBin := os.Getenv("KERI_DRIVER_PYTHON")
	if pythonBin == "" {
		pythonBin = "python3"
	}

	port := os.Getenv("KERI_DRIVER_PORT")
	if port == "" {
		port = "9999"
	}

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

	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start KERI driver: %w", err)
	}

	d.process = cmd
	log.Printf("[keri-driver] Python process started (PID: %d)", cmd.Process.Pid)

	return d.waitForReady(15 * time.Second)
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

func (d *KeriDriver) CreateInception(publicKey, nextPublicKey string) (*DriverInceptionResponse, error) {
	return d.postInception(publicKey, nextPublicKey, "")
}

func (d *KeriDriver) CreateInceptionNamed(publicKey, nextPublicKey, name string) (*DriverInceptionResponse, error) {
	return d.postInception(publicKey, nextPublicKey, name)
}

func (d *KeriDriver) postInception(publicKey, nextPublicKey, name string) (*DriverInceptionResponse, error) {
	reqBody := DriverInceptionRequest{
		PublicKey:     publicKey,
		NextPublicKey: nextPublicKey,
		Name:          name,
	}

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
	reqBody := DriverRotationRequest{
		Name:             name,
		NewPublicKey:     newPublicKey,
		NewNextPublicKey: newNextPublicKey,
	}

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

func (d *KeriDriver) GetKel(name string) (*DriverKelResponse, error) {
	resp, err := d.client.Get(fmt.Sprintf("%s/kel?name=%s", d.BaseURL, name))
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

func (d *KeriDriver) IssueCredential(name string, claims map[string]interface{}, schemaSaid, holderAid string) (*DriverIssueCredentialResponse, error) {
	reqBody := DriverIssueCredentialRequest{
		Name:       name,
		Claims:     claims,
		SchemaSaid: schemaSaid,
		HolderAid:  holderAid,
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

func (d *KeriDriver) GenerateMultisigEvent(aids []string, threshold int, currentKeys []string, eventType string) (*DriverMultisigResponse, error) {
	reqBody := DriverMultisigRequest{
		AIDs:        aids,
		Threshold:   threshold,
		CurrentKeys: currentKeys,
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
