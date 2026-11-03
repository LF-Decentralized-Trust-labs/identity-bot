package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// What key state a key log establishes, for whoever is holding a copy of one
// (ADR-061 section 9).
//
// A signer outside this Identity Agent that has to learn which key is in force,
// an app reading its identity's witnesses, sends each copy here and is told
// what that copy establishes, judged as every log is (keri.ValidateSignedKEL).
// It computes over what it is sent: it fetches nothing, stores nothing, and
// says nothing about any identity it holds. Public, because a signer has to
// learn the key in force before it can sign as the owner, and rate-limited
// like every route that checks a stranger's log.

// An identity's whole log, not a sign-in's few events: bounded so one request
// cannot hold this Identity Agent for long, and checked under the same per-caller
// share as every other route that checks a stranger's log.
const maxKeyStateBody = 4 << 20

type keyStateRequest struct {
	AID string `json:"aid"`
	// Events are the log as messages: each event's bytes and its controller
	// signatures, indexed as KERI attaches them.
	Events []struct {
		RawB64 string   `json:"raw_b64"`
		Sigs   []string `json:"sigs"`
	} `json:"events"`
	// StreamB64 is the log as a CESR stream instead: events followed by their
	// attachments, as KERI implementations exchange them.
	StreamB64 string `json:"stream_b64"`
}

// KeyState is the state a verified key log leaves.
type KeyState struct {
	AID string `json:"aid"`
	// Tip and LastEstablishment name events by sequence number (hexadecimal,
	// as KERI writes it) and digest.
	Tip               map[string]string `json:"tip"`
	LastEstablishment map[string]string `json:"last_establishment"`
	K                 []string          `json:"k"`
	Kt                json.RawMessage   `json:"kt"`
	N                 []string          `json:"n"`
	Nt                json.RawMessage   `json:"nt"`
	// MessagingKeySets are the messaging keysets the log anchors, oldest
	// first; the last is the one the identity is reached on.
	MessagingKeySets []anchoredKeySet `json:"messaging_keysets"`
}

type anchoredKeySet struct {
	S      string          `json:"s"`
	Anchor json.RawMessage `json:"anchor"`
}

func (s *CoreServer) handleKeyState(w http.ResponseWriter, r *http.Request) {
	var req keyStateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxKeyStateBody)).Decode(&req); err != nil || req.AID == "" {
		writeError(w, http.StatusBadRequest, "aid and a key log are required", "send events or stream_b64")
		return
	}
	messages, err := keyStateMessages(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "The key log is unreadable", err.Error())
		return
	}
	state, err := KeyStateOf(req.AID, messages)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "The key log does not establish a key state", err.Error())
		return
	}
	writeJSONResponse(w, state)
}

func keyStateMessages(req keyStateRequest) ([][]byte, error) {
	if req.StreamB64 != "" {
		if len(req.Events) > 0 {
			return nil, fmt.Errorf("send the log as events or as a stream, not both")
		}
		stream, err := base64.StdEncoding.Strict().DecodeString(req.StreamB64)
		if err != nil {
			return nil, fmt.Errorf("stream_b64 is not standard base64: %w", err)
		}
		return keri.ParseKELStream(stream)
	}
	events := make([]drivers.SignedEventBytes, 0, len(req.Events))
	for _, ev := range req.Events {
		events = append(events, drivers.SignedEventBytes{RawB64: ev.RawB64, Sigs: ev.Sigs})
	}
	return drivers.LogMessages(events)
}

// KeyStateOf verifies messages as aid's key log and returns the key state it
// establishes.
func KeyStateOf(aid string, messages [][]byte) (*KeyState, error) {
	if _, err := drivers.VerifiedLogOf(aid, messages); err != nil {
		return nil, err
	}
	state := &KeyState{AID: aid}
	for _, msg := range messages {
		// The event's own fields, read where they lie: the attachments after
		// it are not part of any of them.
		ev, err := keri.ParseEvent(msg)
		if err != nil {
			return nil, err
		}
		if ev.Ilk == "dip" || ev.Delegator != "" {
			// Its delegator's approval is not in what was sent, so the key
			// state it claims cannot be confirmed here.
			return nil, fmt.Errorf("the log of %s is a delegated identity's, and no delegator's log came with it", aid)
		}
		place := map[string]string{"s": fmt.Sprintf("%x", ev.SN), "d": ev.SAID}
		state.Tip = place
		var fields struct {
			Kt json.RawMessage
			Nt json.RawMessage
			A  []json.RawMessage
		}
		for _, f := range ev.Fields {
			switch f.Name {
			case "kt":
				fields.Kt = json.RawMessage(f.Value)
			case "nt":
				fields.Nt = json.RawMessage(f.Value)
			case "a":
				_ = json.Unmarshal(f.Value, &fields.A)
			}
		}
		if ev.Establishment() {
			state.LastEstablishment = place
			state.K, state.N, state.Kt, state.Nt = ev.Keys, ev.NextDigest, fields.Kt, fields.Nt
		}
		for _, a := range messagingSealsAmong(fields.A) {
			state.MessagingKeySets = append(state.MessagingKeySets, anchoredKeySet{S: place["s"], Anchor: a})
		}
	}
	return state, nil
}
