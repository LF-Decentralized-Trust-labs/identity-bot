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
	// PollEvery is how often the machine asks whether the owner has decided;
	// two seconds when zero.
	PollEvery time.Duration
	// WorkItem and Reason are the stated purpose sent, signed, with each call.
	WorkItem string
	// Session names which of the caller's runs is asking, when it has more
	// than one. Signed with each call and passed on to the app a call reaches.
	Session string
	Reason  string

	// brainName and brainModel are the running brain's, for what the host
	// reports with each message.
	brainName, brainModel string
	// signInWait is how long a run waits for a sign-in whose runs are all in
	// use.
	signInWait time.Duration
	// bodyCredential is this body's credential, once read, for the statements
	// it signs.
	bodyCredential string
}

// State is what a host remembers about its enrolment.
type State struct {
	IdentityAgentURL string    `json:"identity_agent_url"`
	IdentityAgent    string    `json:"identity_agent"`
	Agent            string    `json:"agent"`
	AgentName        string    `json:"agent_name"`
	BindingID        string    `json:"binding_id"`
	EnrolledAt       time.Time `json:"enrolled_at"`
	// IdentityAgentKeys are the Identity Agent's sealing keys, as checked
	// against its key log at enrolment. Requests after enrolment are sealed to
	// them.
	IdentityAgentKeys *didcomm.DID `json:"identity_agent_keys,omitempty"`
	// KeyStateSN and KeyStateSAID are the event of the Identity Agent's key
	// log the enrolment string named. A log offered later must still hold it,
	// so an old copy from before it cannot be passed off as current.
	KeyStateSN   int    `json:"key_state_sn,omitempty"`
	KeyStateSAID string `json:"key_state_said,omitempty"`
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
	return h.verifiedLog(e.URL, e.IdentityAgent, func(sn int, said string) bool {
		return sn == e.KeyStateSN && said == e.KeyStateSAID
	})
}

// verifiedLog fetches an identity's key log from the Identity Agent at url and
// accepts it only if it is that identifier's and every event verifies — and,
// when contains is given, only if it holds an event contains accepts. It
// returns the log, as parsed events, and the key it ends with.
func (h *Host) verifiedLog(url, aid string, contains func(sn int, said string) bool) ([]map[string]interface{}, string, error) {
	resp, err := h.client().Get(strings.TrimRight(url, "/") + "/public/oobi/" + aid)
	if err != nil {
		return nil, "", fmt.Errorf("the Identity Agent at %s could not be reached: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("the Identity Agent at %s did not publish the key log of %s (%d)", url, aid, resp.StatusCode)
	}
	var oobi struct {
		AID  string   `json:"aid"`
		Raw  []string `json:"raw_events_b64"`
		Sigs []string `json:"cesr_signatures"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&oobi); err != nil {
		return nil, "", fmt.Errorf("the Identity Agent's key log is unreadable: %w", err)
	}
	if oobi.AID != aid {
		return nil, "", fmt.Errorf("the address answered as %s, not %s", oobi.AID, aid)
	}
	in := drivers.ValidateKELInput{AID: aid}
	named := contains == nil
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
		if ev, err := keri.ParseEvent(raw); err == nil && contains != nil && contains(int(ev.SN), ev.SAID) {
			named = true
		}
	}
	res, err := drivers.ValidateKELFromBytes(in)
	if err != nil || !res.KelVerified {
		return nil, "", fmt.Errorf("the key log of %s does not verify: %v %v", aid, err, res.ValidationErrors)
	}
	if !named {
		return nil, "", fmt.Errorf("the Identity Agent's key log does not contain the event the enrolment string names, so it is not the Identity Agent the string was made by")
	}
	events := make([]map[string]interface{}, 0, len(in.RawEvents))
	for _, raw := range in.RawEvents {
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, "", fmt.Errorf("the key log of %s is unreadable: %w", aid, err)
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
	return h.sealingKeysOf(e.URL, e.IdentityAgent, kel, currentKey)
}

func (h *Host) sealingKeysOf(url, aid string, kel []map[string]interface{}, currentKey string) (*didcomm.DID, error) {
	resp, err := h.client().Get(strings.TrimRight(url, "/") + "/api/didcomm/did?aid=" + aid)
	if err != nil {
		return nil, fmt.Errorf("the Identity Agent's sealing keys could not be fetched: %w", err)
	}
	defer resp.Body.Close()
	var did didcomm.DID
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&did) != nil {
		return nil, fmt.Errorf("the Identity Agent did not publish its sealing keys (%d)", resp.StatusCode)
	}
	if did.AID != aid {
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
	inner, _ := json.Marshal(agentbody.EnrolRequest{
		Secret: e.Secret, Agent: e.Agent, Keys: keys, Nonce: nonce,
		ClaimedGrade: grade, Platform: platform, Placement: placement, Signature: sig,
	})
	env, err := didcomm.PackAuthcrypt(ks, iaKeys, &didcomm.JWM{
		ID: nonce, Type: didcomm.TypeBodyEnrolment,
		From: "did:keri:" + host, To: []string{"did:keri:" + e.IdentityAgent},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), Body: inner,
	})
	if err != nil {
		return State{}, fmt.Errorf("the enrolment could not be sealed: %w", err)
	}
	// The words are shown only once the Identity Agent has taken the request,
	// never before: whoever reads them, a person or a provider's program
	// (ADR-055), may go straight on to report or approve them, and words for a
	// request the Identity Agent does not have yet are refused.
	words := agentbody.Words(host)
	body, _ := json.Marshal(agentbody.SealedEnrolment{Sender: keys, Envelope: env})
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
			"any machine waiting for %q unless it shows this machine's words, %s, and to ask for a new string",
			answer.Error, e.AgentName, strings.Join(words, " "))
	}
	if strings.Join(words, " ") != strings.Join(answer.Words, " ") {
		return State{}, fmt.Errorf("the Identity Agent shows different words for this machine's key — do not approve it")
	}
	fmt.Fprintf(h.out(), "\nThis machine's six words are:\n\n    %s\n\n", strings.Join(words, " "))
	st := State{IdentityAgentURL: strings.TrimRight(e.URL, "/"), IdentityAgent: e.IdentityAgent,
		Agent: e.Agent, AgentName: e.AgentName, BindingID: answer.BindingID, EnrolledAt: time.Now().UTC(),
		IdentityAgentKeys: iaKeys, KeyStateSN: e.KeyStateSN, KeyStateSAID: e.KeyStateSAID}
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
	code, b, err := h.callDirect("GET", "/api/agent-host/binding", nil)
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
		every := h.PollEvery
		if every <= 0 {
			every = 2 * time.Second
		}
		time.Sleep(every)
	}
}

// callDirect sends one request to the Identity Agent, signed by this machine's
// key and not sealed: for the enrolment status only, which a machine asks
// before it is a body the Identity Agent will take sealed requests from.
func (h *Host) callDirect(method, path string, body []byte) (int, []byte, error) {
	st, err := h.loadState()
	if err != nil {
		return 0, nil, fmt.Errorf("this machine has not enrolled: %w", err)
	}
	req, err := http.NewRequest(method, st.IdentityAgentURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	headers, err := h.signedHeaders(method, req.URL.RequestURI(), body)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, err
}

// signedHeaders are the headers that make a request this body's: its
// identifier, and its signature over the request target exactly as sent, a
// timestamp, a fresh nonce, the body and the stated purpose.
func (h *Host) signedHeaders(method, target string, body []byte) (map[string]string, error) {
	// The Identity Agent this machine enrolled with, named inside the signature
	// so no other Identity Agent will take a copy.
	st, err := h.loadState()
	if err != nil {
		return nil, fmt.Errorf("this machine has not enrolled: %w", err)
	}
	signer, _ := h.signer()
	host, _, err := agentbody.Identity(signer)
	if err != nil {
		return nil, err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	sig, err := agentbody.Sign(signer, agentbody.SignedRequest{
		For: st.IdentityAgent, Host: host, Method: method, Target: target, Timestamp: ts, Nonce: nonce, Body: body,
		WorkItem: h.WorkItem, Reason: h.Reason, Session: h.Session,
	}.Bytes())
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		agentbody.HeaderHost: host, agentbody.HeaderSignature: sig,
		agentbody.HeaderTimestamp: ts, agentbody.HeaderNonce: nonce,
		agentbody.HeaderFor: st.IdentityAgent,
	}
	if h.Session != "" {
		out[agentbody.HeaderSession] = h.Session
	}
	if h.WorkItem != "" {
		out[agentbody.HeaderWorkItem] = h.WorkItem
	}
	if h.Reason != "" {
		out[agentbody.HeaderReason] = h.Reason
	}
	if len(body) > 0 {
		out["Content-Type"] = "application/json"
	}
	return out, nil
}

func wordsLine(v interface{}) string {
	list, _ := v.([]interface{})
	out := make([]string, 0, len(list))
	for _, w := range list {
		out = append(out, fmt.Sprint(w))
	}
	return strings.Join(out, " ")
}
