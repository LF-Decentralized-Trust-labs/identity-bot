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
	// WorkItem and Reason are the stated purpose sent, signed, with each call.
	WorkItem string
	Reason   string
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
	// On Windows the TPM key has one fixed name for the whole machine, and it is
	// already the Identity Agent's own controller key there. A body must have a
	// key of its own, so Windows uses a key file, at the software grade, until a
	// per-body TPM key is built and tested. On a Mac the Secure Enclave key is
	// kept per data directory, so the body's is its own.
	var s secureenclave.PlatformSigner
	if runtime.GOOS == "windows" {
		s = secureenclave.NewSoftwareSigner(h.DataDir)
	} else {
		s = secureenclave.NewPlatformSigner(h.DataDir)
	}
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
	_, _, err := h.verifiedIdentityAgent(e)
	return err
}

// verifiedIdentityAgent is CheckIdentityAgent, returning the verified log, as
// parsed events, and the key it ends with.
func (h *Host) verifiedIdentityAgent(e agentbody.Enrolment) ([]map[string]interface{}, string, error) {
	resp, err := h.client().Get(strings.TrimRight(e.URL, "/") + "/public/oobi/" + e.IdentityAgent)
	if err != nil {
		return nil, "", fmt.Errorf("the Identity Agent at %s could not be reached: %w", e.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("the Identity Agent at %s did not publish its key log (%d)", e.URL, resp.StatusCode)
	}
	var oobi struct {
		AID  string   `json:"aid"`
		Raw  []string `json:"raw_events_b64"`
		Sigs []string `json:"cesr_signatures"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&oobi); err != nil {
		return nil, "", fmt.Errorf("the Identity Agent's key log is unreadable: %w", err)
	}
	if oobi.AID != e.IdentityAgent {
		return nil, "", fmt.Errorf("the address answered as %s, not the Identity Agent the enrolment string names (%s)", oobi.AID, e.IdentityAgent)
	}
	in := drivers.ValidateKELInput{AID: e.IdentityAgent}
	named := false
	for i, r := range oobi.Raw {
		raw, err := base64.StdEncoding.DecodeString(r)
		if err != nil {
			return nil, "", fmt.Errorf("event %d of the Identity Agent's key log is unreadable", i)
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
		return nil, "", fmt.Errorf("the Identity Agent's key log does not verify: %v %v", err, res.ValidationErrors)
	}
	if !named {
		return nil, "", fmt.Errorf("the Identity Agent's key log does not contain the event the enrolment string names, so it is not the Identity Agent the string was made by")
	}
	events := make([]map[string]interface{}, 0, len(in.RawEvents))
	for _, raw := range in.RawEvents {
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, "", fmt.Errorf("the Identity Agent's key log is unreadable: %w", err)
		}
		events = append(events, m)
	}
	return events, res.CurrentPublicKey, nil
}

// identityAgentSealingKeys fetches the keys the enrolment is sealed to, and
// accepts them only if they belong to the Identity Agent whose log was just
// verified — committed to in its founding event, or signed by the key its log
// ends with. Whoever answers the request does not get to choose them.
func (h *Host) identityAgentSealingKeys(e agentbody.Enrolment, kel []map[string]interface{}, currentKey string) (*didcomm.DID, error) {
	resp, err := h.client().Get(strings.TrimRight(e.URL, "/") + "/api/didcomm/did?aid=" + e.IdentityAgent)
	if err != nil {
		return nil, fmt.Errorf("the Identity Agent's sealing keys could not be fetched: %w", err)
	}
	defer resp.Body.Close()
	var did didcomm.DID
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&did) != nil {
		return nil, fmt.Errorf("the Identity Agent did not publish its sealing keys (%d)", resp.StatusCode)
	}
	if did.AID != e.IdentityAgent {
		return nil, fmt.Errorf("the sealing keys offered are %s's, not the Identity Agent's", did.AID)
	}
	if _, err := didcomm.CheckKeysBelongTo(&did, kel, currentKey); err != nil {
		return nil, fmt.Errorf("the sealing keys offered do not belong to the Identity Agent: %w", err)
	}
	return &did, nil
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
	// A machine that is already a body says so, before showing words or using
	// the string. Re-running the command it enrolled with is not a stranger
	// racing for the string, and must not be reported as one.
	if st, err := h.loadState(); err == nil && st.IdentityAgent == e.IdentityAgent {
		if status, serr := h.Status(); serr == nil {
			switch {
			case status["state"] == agentbody.StateActive && st.Agent == e.Agent:
				fmt.Fprintf(h.out(), "This machine is already the body of %q, at grade %v. Nothing to do.\n", st.AgentName, status["grade"])
				return st, nil
			case status["state"] == agentbody.StatePending && st.Agent == e.Agent:
				fmt.Fprintf(h.out(), "This machine already asked to become the body of %q and is waiting for a decision.\n"+
					"Its six words are:\n\n    %s\n\n", st.AgentName, wordsLine(status["words"]))
				return st, h.waitForDecision(wait)
			case status["state"] == agentbody.StateActive:
				return State{}, fmt.Errorf("this machine's key is already the body of %q; a machine hosting another AI agent "+
					"uses a separate key — run this again with --data-dir pointing at a new directory", st.AgentName)
			}
		}
	}
	if err := os.MkdirAll(h.DataDir, 0o700); err != nil {
		return State{}, err
	}
	// MkdirAll leaves an existing directory as it was; the sealing keys and
	// the key file live here, so it is tightened either way.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(h.DataDir, 0o700); err != nil {
			return State{}, err
		}
	}
	kel, currentKey, err := h.verifiedIdentityAgent(e)
	if err != nil {
		return State{}, err
	}
	iaKeys, err := h.identityAgentSealingKeys(e, kel, currentKey)
	if err != nil {
		return State{}, err
	}
	fmt.Fprintf(h.out(), "Checked the Identity Agent %s at %s, and its sealing keys.\n", e.IdentityAgent, e.URL)

	signer, grade := h.signer()
	host, verkey, err := agentbody.Identity(signer)
	if err != nil {
		return State{}, fmt.Errorf("this machine's key is unavailable: %w", err)
	}
	ks, err := h.keySet(host)
	if err != nil {
		return State{}, err
	}
	keys, err := agentbody.KeysFrom(host, verkey, ks)
	if err != nil {
		return State{}, err
	}
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
	inner, _ := json.Marshal(map[string]any{
		"secret": e.Secret, "agent": e.Agent, "keys": keys, "nonce": nonce,
		"claimed_grade": grade, "platform": platform, "placement": placement, "signature": sig,
	})
	env, err := didcomm.PackAuthcrypt(ks, iaKeys, &didcomm.JWM{
		ID: nonce, Type: didcomm.TypeBodyEnrolment,
		From: "did:keri:" + host, To: []string{"did:keri:" + e.IdentityAgent},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), Body: inner,
	})
	if err != nil {
		return State{}, fmt.Errorf("the enrolment could not be sealed: %w", err)
	}
	words := agentbody.Words(host)
	fmt.Fprintf(h.out(), "\nThis machine's six words are:\n\n    %s\n\n", strings.Join(words, " "))
	body, _ := json.Marshal(map[string]any{"sender": keys, "envelope": env})
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
		return State{}, fmt.Errorf("the Identity Agent refused this enrolment: %s\n"+
			"If the string was already used, another machine may have used it. Tell the owner NOT to approve "+
			"any machine waiting for %q unless it shows the words above, and to ask for a new string", answer.Error, e.AgentName)
	}
	if strings.Join(words, " ") != strings.Join(answer.Words, " ") {
		return State{}, fmt.Errorf("the Identity Agent shows different words for this machine's key — do not approve it")
	}
	st := State{IdentityAgentURL: strings.TrimRight(e.URL, "/"), IdentityAgent: e.IdentityAgent,
		Agent: e.Agent, AgentName: e.AgentName, BindingID: answer.BindingID, EnrolledAt: time.Now().UTC()}
	if err := h.saveState(st); err != nil {
		return State{}, err
	}
	fmt.Fprintf(h.out(), "This machine is asking to become the body of %q, at grade %s.\n", e.AgentName, grade)
	fmt.Fprintf(h.out(), "Approve it in the app only if it shows exactly the six words above.\n")
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
	req, err := http.NewRequest(method, st.IdentityAgentURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return 0, nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	sig, err := agentbody.Sign(signer, agentbody.SignedRequest{
		Host: host, Method: method, Target: req.URL.RequestURI(), Timestamp: ts, Nonce: nonce, Body: body,
		WorkItem: h.WorkItem, Reason: h.Reason,
	}.Bytes())
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(agentbody.HeaderHost, host)
	req.Header.Set(agentbody.HeaderSignature, sig)
	req.Header.Set(agentbody.HeaderTimestamp, ts)
	req.Header.Set(agentbody.HeaderNonce, nonce)
	if h.WorkItem != "" {
		req.Header.Set(agentbody.HeaderWorkItem, h.WorkItem)
	}
	if h.Reason != "" {
		req.Header.Set(agentbody.HeaderReason, h.Reason)
	}
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

func wordsLine(v interface{}) string {
	list, _ := v.([]interface{})
	out := make([]string, 0, len(list))
	for _, w := range list {
		out = append(out, fmt.Sprint(w))
	}
	return strings.Join(out, " ")
}
