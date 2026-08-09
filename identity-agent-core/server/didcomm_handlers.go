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
	"identity-agent-core/login"
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

func (s *CoreServer) loadDIDCommKeys() map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if b, err := os.ReadFile(s.didcommKeysPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// writeFileAtomic replaces a file in one step, or leaves the old one alone.
//
// These three files were each written with a bare os.WriteFile: truncate, then
// write. A process that stopped in between left a half-written file, and every
// reader here discards the unmarshal error and carries on with an empty map. So
// an interrupted write did not fail loudly — it silently emptied the peers list,
// the inbox, or the file holding this agent's DIDComm private keys.
//
// Writing beside the target and renaming means a reader sees either the old
// file or the new one. Losing the newest change is recoverable; a truncated key
// file is not.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (s *CoreServer) saveDIDCommKeys(m map[string]json.RawMessage) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.didcommKeysPath(), b, 0600)
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

// storeKeySetFor files an already-minted keyset under aid.
//
// Separate from keySetFor because the order is reversed at inception: the keys
// have to exist before the identifier does, since the identifier is derived
// from an event that commits to them. Refuses to overwrite, because the only
// way to reach that case is a second identity claiming an identifier that
// already has keys, and silently replacing them would strand every message
// anyone had already encrypted to the first set.
func (s *CoreServer) storeKeySetFor(aid string, ks *didcomm.KeySet) error {
	if aid == "" {
		return fmt.Errorf("a keyset must be filed under an identifier")
	}
	didcommMu.Lock()
	defer didcommMu.Unlock()
	keys := s.loadDIDCommKeys()
	if _, exists := keys[aid]; exists {
		return fmt.Errorf("%s already has messaging keys, which will not be replaced", aid)
	}
	ks.AID = aid
	blob, err := ks.Marshal()
	if err != nil {
		return err
	}
	keys[aid] = blob
	return s.saveDIDCommKeys(keys)
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
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.didcommPeersPath(), b, 0600)
}

// --- replay: in-process seen-ID cache (id -> expiry) ---

// maxEnvelopeLifetime bounds how far ahead a sender may declare its envelope
// valid.
//
// Freshness was entirely the sender's to decide: the receiver parsed
// expires_time and checked only that it had not passed. A peer could declare an
// envelope valid until 2099, and two things followed. Its id had to be
// remembered until then, so the replay cache could be filled with entries that
// never evict; and because that cache is per-process, the envelope became
// replayable in full after any restart, for as long as the sender chose.
//
// An hour is far more than the ten minutes our own sender uses, so it constrains
// nobody honest.
const maxEnvelopeLifetime = time.Hour

// maxSeenEntries caps the replay cache.
//
// The sweep below walks every entry on every call, so an unbounded map is not
// merely memory: cost per message grows with the number of entries a peer has
// planted, and the agent degrades in a way that does not recover until it
// restarts — which is also the event that empties the cache and makes
// everything in it replayable again.
const maxSeenEntries = 50000

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
	// Full after the sweep means live entries alone have filled it. Refusing to
	// record is the safe direction: the message is still delivered, and the
	// worst case is that a duplicate of it is accepted later. Evicting a live
	// entry instead would make a chosen message replayable on demand, which is
	// the attack this cache exists to stop.
	if len(didcommSeen.m) >= maxSeenEntries {
		return false
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
		Endpoint: canonicalPeerEndpoint(fmt.Sprintf("http://127.0.0.1:%d", s.Port)),
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
	if !s.hasKeySet(aid) && !s.isOwner(r) {
		// A stranger cannot make this agent generate keys for an arbitrary
		// identifier — that is unbounded work on demand. But refusing outright
		// broke the case this endpoint exists for: an agent that has never sent
		// a DIDComm message has no keyset, so nobody could ever encrypt the
		// FIRST message to it. Every newly created agent is in that state, and
		// the first message is exactly the one that has to get through.
		//
		// So one exception, bounded to one keyset: our OWN identity. It is going
		// to exist the moment we send anything, there is exactly one of it, and
		// generating it cannot be repeated for a second identifier.
		if identity, err := s.DataStore.GetIdentity(); err != nil || identity == nil || identity.AID != aid {
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

	// Vouch for these keys with the identity's own signing key.
	//
	// Without this the keys are whatever this endpoint returned, and whoever
	// answers it decides what a counterparty encrypts to. A signature ties them
	// to the identifier instead: the receiving side checks it against the key
	// that identifier's own history ends with, so substituting keys means
	// substituting the identity.
	//
	// Best effort at this layer. An agent that cannot sign — because the key
	// lives on a device that is not this one — still publishes its keys, and
	// the receiving side decides what an unvouched-for set is worth. Refusing
	// here would take an agent off the air for a reason its counterparties
	// cannot see.
	if seed, serr := s.identitySigningSeed(); serr == nil {
		if sig, kerr := login.SignString(string(did.SigningInput()), seed); kerr == nil {
			did.KelSig = sig
		} else {
			log.Printf("[didcomm] could not vouch for this agent's keys: %v", kerr)
		}
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
	peers[req.DID.AID] = peerRecord{AID: req.DID.AID, DID: req.DID, Endpoint: canonicalPeerEndpoint(req.Endpoint), AddedAt: time.Now().UTC()}
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
		// The peers file is the ONLY authority on this path, and registering a
		// peer is an owner action.
		//
		// This used to fall through to ensureLocalPeer, which registers one of
		// our own provisioned agents on demand. On the owner's send path that is
		// convenience; here it was a stranger's. Pairwise AIDs are published in
		// OOBI URLs, so anyone who read one could make an unauthenticated POST
		// mint a post-quantum keyset and write two files — before a single byte
		// was authenticated. The envelope would still fail to decrypt, so it was
		// never a way in; it was a way to make this agent do expensive work on
		// demand, and it contradicted the rule the neighbouring handler states
		// plainly: never mint for an anonymous caller.
		//
		// A local agent that needs to reach us is registered when the owner
		// first sends to it, which is the same ceremony as any other peer.
		//
		// One exception, and it is not a weakening: a sender the owner has
		// ALREADY ACCEPTED as a contact. The relationship exists and the address
		// is on file; only the messaging keyset was never fetched, which is why
		// a first message from somebody you know was refused. Resolving that
		// finishes a step the owner authorised rather than trusting the caller.
		// A stranger still gets nothing, and nothing is fetched on their say-so.
		resolved, rerr := s.resolveKnownContactAsPeer(skid)
		if rerr != nil {
			log.Printf("[identity-agent-core] could not reach an accepted contact's agent: %v", rerr)
		}
		if !resolved {
			// A stranger who brought their own proof.
			//
			// Not a weakening of the rule above: nothing is fetched, nothing is
			// minted, and nothing is stored. The sender presents its key
			// history, this agent checks that the history digests to the
			// identifier being claimed and takes the messaging keys out of it,
			// and the ONLY thing that can then happen is a request appearing in
			// front of the owner. Proving your name is not being agreed to.
			if handled := s.tryFirstContact(w, r, skid, &env); handled {
				return
			}
			jsonError(w, "sender is not a registered peer", http.StatusForbidden)
			return
		}
		didcommMu.Lock()
		peer, known = s.loadPeers()[skid]
		didcommMu.Unlock()
		if !known {
			jsonError(w, "sender is not a registered peer", http.StatusForbidden)
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
	// A sender does not get to decide how long we remember it for. See
	// maxEnvelopeLifetime.
	if exp.After(time.Now().Add(maxEnvelopeLifetime)) {
		jsonError(w, "envelope_lifetime_too_long", http.StatusForbidden)
		return
	}
	if seenBefore(jwm.ID, exp) {
		jsonError(w, "replay_detected", http.StatusConflict)
		return
	}
	// Store the received message.
	//
	// One table, not two. This used to append to didcomm_inbox.json, a flat file
	// with the same fields as a notification — from, to, type, body, verified —
	// but no id, no read state and no pruning. Both were inboxes; keeping them
	// separate meant the next person had to learn which held what.
	//
	// skid and kid are the AUTHENTICATED header values, not anything read out of
	// the message. A sender that could name itself could name somebody else.
	s.storeInboundAsNotification(skid, kid, jwm, true)
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
	// Reads the notification table now, and renders the same shape it always
	// did. The messages this returns are the same messages; only where they are
	// kept has changed, and a client that has not been updated should not have
	// to care.
	stored, err := s.DataStore.GetNotifications("", 0)
	if err != nil {
		jsonError(w, "failed to read inbox", http.StatusInternalServerError)
		return
	}
	list := []inboxEntry{}
	for _, n := range stored {
		list = append(list, inboxEntry{
			ReceivedAt: n.ReceivedAt,
			FromAID:    n.FromAID,
			ToAID:      n.ToAID,
			Type:       n.Kind,
			MessageID:  n.ID,
			Body:       json.RawMessage(n.Payload),
			Mode:       "authcrypt",
			Verified:   n.Verified,
		})
	}
	// Already newest first from the store.
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
	// An action registered for this type performs it. The envelope has already
	// established who sent it, that it is fresh, and that it has not been seen
	// before, so what arrives here is authenticated in a way a plaintext POST to
	// a REST endpoint never was.
	if s.dispatchInbound(InboundMessage{
		ToAID: toAID, FromAID: fromAID, Type: jwm.Type, Body: jwm.Body, MessageID: jwm.ID,
	}) {
		return
	}

	// Nothing registered: the behaviour that existed before. An overlay may add
	// its own handling, and otherwise the message is already stored and this
	// says so.
	if s.inboundDIDComm != nil {
		go s.inboundDIDComm(toAID, fromAID, jwm.Type, jwm.Body, jwm.ID)
		return
	}
	log.Printf("[didcomm] received %s %s for %s (stored in inbox)", jwm.Type, jwm.ID, toAID)
}
