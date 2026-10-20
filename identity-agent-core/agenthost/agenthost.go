// Package agenthost is the machine's side of becoming an AI agent's body: the
// agent-host program's working parts, kept apart from its command line so they
// can be tested end to end.
//
// A host does three things in this version:
//
//   - Enrol: read an enrolment string, check the Identity Agent it names against
//     its published key log, make or load this machine's key, send the enrolment
//     signed by it, show the six words, and wait for the owner's decision.
//   - Report its status: ask, signed, whether it was approved.
//   - Sign requests: send a request to the Identity Agent signed by the machine
//     key, which the Identity Agent takes as the AI agent's.
//
// The machine key is the same secure-hardware key the Identity Agent itself
// uses where it acts as a controller (secureenclave.NewPlatformSigner): the
// Secure Enclave on a Mac, the TPM on Windows, and a key file elsewhere. Only
// what the key is used FOR differs.
package agenthost

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/secureenclave"

	keri "github.com/grapeid/keri-go"
)

// Host is one machine's agent-host state, kept in its own data directory.
type Host struct {
	DataDir string
	// Signer is the machine key. Nil means the platform's own, as the Identity
	// Agent's controller key is made.
	Signer agentbody.Signer
	// Hardware reports whether Signer is held in secure hardware. Ignored when
	// Signer is nil: the platform signer reports it.
	Hardware bool
	// HTTP is the client for talking to the Identity Agent.
	HTTP *http.Client
	// Out receives what a person at the machine should read.
	Out io.Writer
}

// State is what a host remembers about its enrolment.
type State struct {
	IdentityAgentURL string    `json:"identity_agent_url"`
	IdentityAgent    string    `json:"identity_agent"`
	Agent            string    `json:"agent"`
	AgentName        string    `json:"agent_name"`
	BindingID        string    `json:"binding_id"`
	EnrolledAt       time.Time `json:"enrolled_at"`
}

// DefaultDataDir is where a host keeps its key and state, per operating system.
func DefaultDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "Agent Host")
	case "windows":
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "Agent Host")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "agent-host")
}

func (h *Host) out() io.Writer {
	if h.Out == nil {
		return io.Discard
	}
	return h.Out
}

func (h *Host) client() *http.Client {
	if h.HTTP == nil {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return h.HTTP
}

// signer is the machine key, and the grade the machine can claim for it.
func (h *Host) signer() (agentbody.Signer, string) {
	if h.Signer != nil {
		if h.Hardware {
			return h.Signer, agentbody.GradeHardwareAsserted
		}
		return h.Signer, agentbody.GradeSoftware
	}
	s := secureenclave.NewPlatformSigner(h.DataDir)
	if secureenclave.UsingHardware(s) {
		return s, agentbody.GradeHardwareAsserted
	}
	return s, agentbody.GradeSoftware
}

// keySet is the machine's sealing keys, made once and kept in its data
// directory. They are software keys — secure hardware does neither X25519 nor
// ML-KEM — which is why the machine key signs them at enrolment.
func (h *Host) keySet(host string) (*didcomm.KeySet, error) {
	path := filepath.Join(h.DataDir, "sealing_keys.json")
	if b, err := os.ReadFile(path); err == nil {
		return didcomm.UnmarshalKeySet(b)
	}
	ks, err := didcomm.GenerateKeySet(host)
	if err != nil {
		return nil, err
	}
	b, err := ks.Marshal()
	if err != nil {
		return nil, err
	}
	return ks, os.WriteFile(path, b, 0o600)
}

func (h *Host) loadState() (State, error) {
	var st State
	b, err := os.ReadFile(filepath.Join(h.DataDir, "host.json"))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func (h *Host) saveState(st State) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(filepath.Join(h.DataDir, "host.json"), b, 0o600)
}

// CheckIdentityAgent fetches the Identity Agent's key log from the address in
// the enrolment string and accepts it only if it is the log the string names:
// the right identifier, every event signed and verified, and containing the
// named event. A relay or DNS attacker answering with another key fails here,
// before the machine sends anything.
func (h *Host) CheckIdentityAgent(e agentbody.Enrolment) error {
	resp, err := h.client().Get(strings.TrimRight(e.URL, "/") + "/public/oobi/" + e.IdentityAgent)
	if err != nil {
		return fmt.Errorf("the Identity Agent at %s could not be reached: %w", e.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the Identity Agent at %s did not publish its key log (%d)", e.URL, resp.StatusCode)
	}
	var oobi struct {
		AID  string   `json:"aid"`
		Raw  []string `json:"raw_events_b64"`
		Sigs []string `json:"cesr_signatures"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&oobi); err != nil {
		return fmt.Errorf("the Identity Agent's key log is unreadable: %w", err)
	}
	if oobi.AID != e.IdentityAgent {
		return fmt.Errorf("the address answered as %s, not the Identity Agent the enrolment string names (%s)", oobi.AID, e.IdentityAgent)
	}
	in := drivers.ValidateKELInput{AID: e.IdentityAgent}
	named := false
	for i, r := range oobi.Raw {
		raw, err := base64.StdEncoding.DecodeString(r)
		if err != nil {
			return fmt.Errorf("event %d of the Identity Agent's key log is unreadable", i)
		}
		in.RawEvents = append(in.RawEvents, raw)
		sig := ""
		if i < len(oobi.Sigs) {
			sig = oobi.Sigs[i]
		}
		in.CesrSignatures = append(in.CesrSignatures, sig)
		if ev, err := keri.ParseEvent(raw); err == nil && int(ev.SN) == e.KeyStateSN && ev.SAID == e.KeyStateSAID {
			named = true
		}
	}
	res, err := drivers.ValidateKELFromBytes(in)
	if err != nil || !res.KelVerified {
		return fmt.Errorf("the Identity Agent's key log does not verify: %v %v", err, res.ValidationErrors)
	}
	if !named {
		return fmt.Errorf("the Identity Agent's key log does not contain the event the enrolment string names, so it is not the Identity Agent the string was made by")
	}
	return nil
}

// ErrRejected is the owner saying the words did not match.
var ErrRejected = errors.New("the owner rejected this machine: the words did not match. Ask them for a new enrolment string")

// Enrol runs the machine's side of the ceremony and returns once the owner has
// decided, or wait has passed.
func (h *Host) Enrol(enrolment string, placement string, wait time.Duration) (State, error) {
	e, err := agentbody.ParseEnrolment(enrolment)
	if err != nil {
		return State{}, err
	}
	if !e.Expires.IsZero() && time.Now().After(e.Expires) {
		return State{}, fmt.Errorf("this enrolment string expired at %s; ask for a new one", e.Expires.Local().Format(time.Kitchen))
	}
	if err := os.MkdirAll(h.DataDir, 0o700); err != nil {
		return State{}, err
	}
	if err := h.CheckIdentityAgent(e); err != nil {
		return State{}, err
	}
	fmt.Fprintf(h.out(), "Checked the Identity Agent %s at %s.\n", e.IdentityAgent, e.URL)

	signer, grade := h.signer()
	host, verkey, err := agentbody.Identity(signer)
	if err != nil {
		return State{}, fmt.Errorf("this machine's key is unavailable: %w", err)
	}
	ks, err := h.keySet(host)
	if err != nil {
		return State{}, err
	}
	_, _, x, kem, err := ks.PublicMaterial()
	if err != nil {
		return State{}, err
	}
	keys := agentbody.Keys{Host: host, Verkey: verkey,
		X25519: base64.RawURLEncoding.EncodeToString(x), MLKEM768: base64.RawURLEncoding.EncodeToString(kem)}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return State{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	platform := runtime.GOOS + "/" + runtime.GOARCH
	sig, err := agentbody.Sign(signer, agentbody.EnrolProof(e, nonce, keys, grade, platform, placement))
	if err != nil {
		return State{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"secret": e.Secret, "agent": e.Agent, "keys": keys, "nonce": nonce,
		"claimed_grade": grade, "platform": platform, "placement": placement, "signature": sig,
	})
	resp, err := h.client().Post(strings.TrimRight(e.URL, "/")+"/api/agent-host/enrol", "application/json", bytes.NewReader(body))
	if err != nil {
		return State{}, err
	}
	defer resp.Body.Close()
	var answer struct {
		BindingID string   `json:"binding_id"`
		Words     []string `json:"words"`
		Error     string   `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&answer)
	if resp.StatusCode != http.StatusAccepted {
		return State{}, fmt.Errorf("the Identity Agent refused this enrolment: %s", answer.Error)
	}
	words := agentbody.Words(host)
	if strings.Join(words, " ") != strings.Join(answer.Words, " ") {
		return State{}, fmt.Errorf("the Identity Agent shows different words for this machine's key — do not approve it")
	}
	st := State{IdentityAgentURL: strings.TrimRight(e.URL, "/"), IdentityAgent: e.IdentityAgent,
		Agent: e.Agent, AgentName: e.AgentName, BindingID: answer.BindingID, EnrolledAt: time.Now().UTC()}
	if err := h.saveState(st); err != nil {
		return State{}, err
	}
	fmt.Fprintf(h.out(), "\nThis machine is asking to become the body of %q, at grade %s.\n", e.AgentName, grade)
	fmt.Fprintf(h.out(), "Check that the Identity Agent shows exactly these six words, then approve it there:\n\n    %s\n\n", strings.Join(words, " "))
	return st, h.waitForDecision(wait)
}

// Status asks the Identity Agent, signed by this machine's key, where its
// enrolment stands.
func (h *Host) Status() (map[string]any, error) {
	var out map[string]any
	code, b, err := h.Call("GET", "/api/agent-host/binding", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("status %d: %s", code, b)
	}
	if code != http.StatusOK {
		return out, fmt.Errorf("status %d: %v", code, out["error"])
	}
	return out, nil
}

func (h *Host) waitForDecision(wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		st, err := h.Status()
		if err == nil {
			switch st["state"] {
			case agentbody.StateActive:
				fmt.Fprintf(h.out(), "Approved. This machine is now the body of the AI agent, at grade %v.\n", st["grade"])
				return nil
			case agentbody.StateRejected:
				return ErrRejected
			case agentbody.StateRevoked:
				return fmt.Errorf("this machine was the AI agent's body, and that has been revoked")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no decision yet; run `agent-host status` to check again")
		}
		time.Sleep(2 * time.Second)
	}
}

// Call sends one request to the Identity Agent, signed by this machine's key.
func (h *Host) Call(method, path string, body []byte) (int, []byte, error) {
	st, err := h.loadState()
	if err != nil {
		return 0, nil, fmt.Errorf("this machine has not enrolled: %w", err)
	}
	signer, _ := h.signer()
	host, _, err := agentbody.Identity(signer)
	if err != nil {
		return 0, nil, err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	sig, err := agentbody.Sign(signer, agentbody.RequestToSign(host, method, path, ts, body))
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(method, st.IdentityAgentURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(agentbody.HeaderHost, host)
	req.Header.Set(agentbody.HeaderSignature, sig)
	req.Header.Set(agentbody.HeaderTimestamp, ts)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, err
}
