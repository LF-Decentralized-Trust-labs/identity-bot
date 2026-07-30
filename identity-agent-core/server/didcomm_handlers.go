package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/didcomm"
)

// DIDComm wiring — the encrypted, mutually-authenticated IA-to-IA transport.
//
// This IA holds a hybrid DIDComm keyset per local AID (didcomm_keys.json), a registry
// of peer DIDs + endpoints it has exchanged with (didcomm_peers.json), and an inbox of
// received messages (didcomm_inbox.json). Establishing a relationship = both sides
// register each other's DID. Then either can authcrypt to the other's pairwise AID.
//
// Public surface: POST /didcomm (inbound envelopes) and GET /api/didcomm/did (this
// IA's public keys for an AID). Owner surface: register peers, send, read the inbox.
// Private keys live in a 0600 file in the data dir (vault-encryption is a follow-up).

var didcommMu sync.Mutex

type peerRecord struct {
	AID      string      `json:"aid"`
	DID      didcomm.DID `json:"did"`
	Endpoint string      `json:"endpoint"` // e.g. https://host/didcomm
	AddedAt  time.Time   `json:"added_at"`
}

type inboxEntry struct {
	ReceivedAt string          `json:"received_at"`
	FromAID    string          `json:"from_aid"`
	ToAID      string          `json:"to_aid"`
	Type       string          `json:"type"`
	MessageID  string          `json:"message_id"`
	Body       json.RawMessage `json:"body"`
	Mode       string          `json:"mode"`
	Verified   bool            `json:"verified"` // hybrid signature + both KA halves passed
}

func (s *CoreServer) didcommKeysPath() string  { return filepath.Join(s.DataDir, "didcomm_keys.json") }
func (s *CoreServer) didcommPeersPath() string { return filepath.Join(s.DataDir, "didcomm_peers.json") }
func (s *CoreServer) didcommInboxPath() string { return filepath.Join(s.DataDir, "didcomm_inbox.json") }

func (s *CoreServer) loadDIDCommKeys() map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if b, err := os.ReadFile(s.didcommKeysPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (s *CoreServer) saveDIDCommKeys(m map[string]json.RawMessage) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(s.didcommKeysPath(), b, 0600)
}

// keySetFor returns the DIDComm keyset for aid, minting + persisting one on first use.
func (s *CoreServer) keySetFor(aid string) (*didcomm.KeySet, error) {
	didcommMu.Lock()
	defer didcommMu.Unlock()
	keys := s.loadDIDCommKeys()
	if blob, ok := keys[aid]; ok {
		return didcomm.UnmarshalKeySet(blob)
	}
	ks, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		return nil, err
	}
	blob, err := ks.Marshal()
	if err != nil {
		return nil, err
	}
	keys[aid] = blob
	if err := s.saveDIDCommKeys(keys); err != nil {
		return nil, err
	}
	return ks, nil
}

// hasKeySet reports whether a keyset already exists for aid (no minting).
func (s *CoreServer) hasKeySet(aid string) bool {
	didcommMu.Lock()
	defer didcommMu.Unlock()
	_, ok := s.loadDIDCommKeys()[aid]
	return ok
}

func (s *CoreServer) loadPeers() map[string]peerRecord {
	m := map[string]peerRecord{}
	if b, err := os.ReadFile(s.didcommPeersPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (s *CoreServer) savePeers(m map[string]peerRecord) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(s.didcommPeersPath(), b, 0600)
}

func (s *CoreServer) appendInbox(e inboxEntry) {
	didcommMu.Lock()
	defer didcommMu.Unlock()
	var list []inboxEntry
	if b, err := os.ReadFile(s.didcommInboxPath()); err == nil {
		_ = json.Unmarshal(b, &list)
	}
	list = append(list, e)
	b, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(s.didcommInboxPath(), b, 0600)
}

// --- replay: in-process seen-ID cache (id -> expiry) ---
var didcommSeen = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

func seenBefore(id string, exp time.Time) bool {
	didcommSeen.Lock()
	defer didcommSeen.Unlock()
	now := time.Now()
	for k, e := range didcommSeen.m {
		if now.After(e) {
			delete(didcommSeen.m, k)
		}
	}
	if _, ok := didcommSeen.m[id]; ok {
		return true
	}
	didcommSeen.m[id] = exp
	return false
}

// ensureLocalPeer registers one of this IA's own provisioned agents as a DIDComm peer
// (minting its keyset + pointing at the loopback /didcomm), so intra-org agent-to-agent
// messaging needs no manual peer exchange. Errors if aid is not a local ai_agent.
func (s *CoreServer) ensureLocalPeer(aid string) (peerRecord, error) {
	if s.findAgentAssetByAID(aid) == nil {
		return peerRecord{}, fmt.Errorf("%s is not a local provisioned agent", aid)
	}
	ks, err := s.keySetFor(aid)
	if err != nil {
		return peerRecord{}, err
	}
	did, err := ks.DID()
	if err != nil {
		return peerRecord{}, err
	}
	rec := peerRecord{
		AID: aid, DID: *did,
		Endpoint: fmt.Sprintf("http://127.0.0.1:%d/didcomm", s.Port),
		AddedAt:  time.Now().UTC(),
	}
	didcommMu.Lock()
	peers := s.loadPeers()
	peers[aid] = rec
	err = s.savePeers(peers)
	didcommMu.Unlock()
	return rec, err
}

// handleListDIDCommPeers lists the registered DIDComm peers (owner only).
func (s *CoreServer) handleListDIDCommPeers(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "peers are owner only", http.StatusForbidden)
		return
	}
	didcommMu.Lock()
	m := s.loadPeers()
	didcommMu.Unlock()
	out := make([]map[string]any, 0, len(m))
	for _, p := range m {
		out = append(out, map[string]any{"aid": p.AID, "endpoint": p.Endpoint, "added_at": p.AddedAt})
	}
	jsonResponse(w, map[string]any{"peers": out})
}

// handleGetDIDCommDID returns this IA's public DID for an AID. Public (public keys);
// mints the keyset lazily when the local owner asks (so the owner can hand the DID to a
// peer), but never mints for an anonymous caller.
func (s *CoreServer) handleGetDIDCommDID(w http.ResponseWriter, r *http.Request) {
	aid := r.URL.Query().Get("aid")
	if aid == "" {
		jsonError(w, "aid is required", http.StatusBadRequest)
		return
	}
	if !s.hasKeySet(aid) {
		if !s.isOwner(r) {
			jsonError(w, "no didcomm identity for that aid", http.StatusNotFound)
			return
		}
	}
	ks, err := s.keySetFor(aid)
	if err != nil {
		jsonError(w, "keyset error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	did, err := ks.DID()
	if err != nil {
		jsonError(w, "did error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, did)
}

// handleRegisterDIDCommPeer records a peer's DID + endpoint (owner only) — the
// relationship-establishment step. After both sides register each other, authcrypt
// works in both directions.
func (s *CoreServer) handleRegisterDIDCommPeer(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "peer registration is owner only", http.StatusForbidden)
		return
	}
	var req struct {
		DID      didcomm.DID `json:"did"`
		Endpoint string      `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DID.AID == "" {
		jsonError(w, "did (with aid) is required", http.StatusBadRequest)
		return
	}
	didcommMu.Lock()
	peers := s.loadPeers()
	peers[req.DID.AID] = peerRecord{AID: req.DID.AID, DID: req.DID, Endpoint: req.Endpoint, AddedAt: time.Now().UTC()}
	err := s.savePeers(peers)
	didcommMu.Unlock()
	if err != nil {
		jsonError(w, "failed to persist peer", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"registered": req.DID.AID, "endpoint": req.Endpoint})
}

// handleSendDIDCommMessage packs an authcrypt envelope from a local AID to a registered
// peer and delivers it over direct HTTPS to the peer's endpoint (owner only).
func (s *CoreServer) handleSendDIDCommMessage(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "sending is owner only", http.StatusForbidden)
		return
	}
	var req struct {
		FromAID string          `json:"from_aid"`
		ToAID   string          `json:"to_aid"`
		Type    string          `json:"type"`
		Body    json.RawMessage `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FromAID == "" || req.ToAID == "" {
		jsonError(w, "from_aid, to_aid, type are required", http.StatusBadRequest)
		return
	}
	if !didcomm.KnownType(req.Type) {
		jsonError(w, "unknown_message_type", http.StatusBadRequest)
		return
	}
	msgID, status, err := s.SendDIDCommMessage(req.FromAID, req.ToAID, req.Type, req.Body)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonResponse(w, map[string]any{
		"delivered":   status == http.StatusAccepted || status == http.StatusOK,
		"message_id":  msgID,
		"peer_status": status,
	})
}

// handleDIDCommInbound is the PUBLIC inbound endpoint (POST {PUBLIC_URL}/didcomm). It
// resolves the recipient keyset by kid, the sender DID by skid (must be a registered
// peer), unpacks + verifies, applies replay protection, and stores the message.
func (s *CoreServer) handleDIDCommInbound(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		jsonError(w, "read error", http.StatusBadRequest)
		return
	}
	var env didcomm.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		jsonError(w, "bad envelope", http.StatusBadRequest)
		return
	}
	skid := env.Protected.Skid
	if skid == "" {
		jsonError(w, "missing skid (anoncrypt not supported in v0)", http.StatusBadRequest)
		return
	}
	// Resolve the sender DID from the peer registry. If the sender is one of THIS IA's
	// own provisioned agents (intra-org A2A), auto-resolve it — its DID is ours.
	didcommMu.Lock()
	peer, known := s.loadPeers()[skid]
	didcommMu.Unlock()
	if !known {
		if p, aerr := s.ensureLocalPeer(skid); aerr == nil {
			peer = p
		} else {
			jsonError(w, "unknown sender "+skid+" — not a registered peer", http.StatusForbidden)
			return
		}
	}
	// Resolve the recipient keyset from kid.
	if len(env.Recipients) == 0 {
		jsonError(w, "no recipient", http.StatusBadRequest)
		return
	}
	kid := env.Recipients[0].Header.Kid
	if !s.hasKeySet(kid) {
		jsonError(w, "unknown_recipient_aid", http.StatusNotFound)
		return
	}
	rcpt, err := s.keySetFor(kid)
	if err != nil {
		jsonError(w, "recipient keyset error", http.StatusInternalServerError)
		return
	}
	jwm, err := didcomm.UnpackAuthcrypt(rcpt, &peer.DID, &env)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnauthorized) // signature_invalid / key_agreement_failed / body_hash_mismatch
		return
	}
	// Replay + freshness (R-1, R-2 / E-6, E-7).
	exp, perr := time.Parse(time.RFC3339, jwm.ExpiresTime)
	if perr != nil || time.Now().After(exp) {
		jsonError(w, "envelope_expired", http.StatusForbidden)
		return
	}
	if seenBefore(jwm.ID, exp) {
		jsonError(w, "replay_detected", http.StatusConflict)
		return
	}
	// Store the received message.
	s.appendInbox(inboxEntry{
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		FromAID:    skid, ToAID: kid, Type: jwm.Type, MessageID: jwm.ID,
		Body: jwm.Body, Mode: env.Mode, Verified: true,
	})
	// The handler layer routes on type; the AI-agent handler picks up agent-* messages.
	s.routeInboundDIDComm(kid, skid, jwm)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "message_id": jwm.ID, "type": jwm.Type})
}

// handleGetDIDCommInbox returns received messages (owner only).
func (s *CoreServer) handleGetDIDCommInbox(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "inbox is owner only", http.StatusForbidden)
		return
	}
	var list []inboxEntry
	if b, err := os.ReadFile(s.didcommInboxPath()); err == nil {
		_ = json.Unmarshal(b, &list)
	}
	if list == nil {
		list = []inboxEntry{}
	}
	// newest first
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	jsonResponse(w, map[string]any{"messages": list})
}

func newMessageID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "msg-" + hex.EncodeToString(b)
}

// InboundDIDCommHandler is invoked for each decrypted, verified inbound message (after
// it is stored in the inbox). An overlay registers one via OnInboundDIDComm to add
// behavior — e.g. answering an agent-message with the recipient agent's brain. The core
// itself only delivers + stores; it does not interpret message bodies.
type InboundDIDCommHandler func(toAID, fromAID, msgType string, body json.RawMessage, jwmID string)

// OnInboundDIDComm registers the overlay's inbound-message handler (server layer, at
// startup). Nil leaves delivery-only behavior.
func (s *CoreServer) OnInboundDIDComm(h InboundDIDCommHandler) { s.inboundDIDComm = h }

// routeInboundDIDComm hands a decrypted, verified message to the registered overlay
// handler (if any). The core stores every message in the inbox regardless; it does not
// interpret bodies or auto-respond — that is the overlay's job.
func (s *CoreServer) routeInboundDIDComm(toAID, fromAID string, jwm *didcomm.JWM) {
	if s.inboundDIDComm != nil {
		go s.inboundDIDComm(toAID, fromAID, jwm.Type, jwm.Body, jwm.ID)
		return
	}
	log.Printf("[didcomm] received %s %s for %s (stored in inbox)", jwm.Type, jwm.ID, toAID)
}
