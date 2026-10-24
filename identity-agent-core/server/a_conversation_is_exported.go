package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"

	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/backup"
	"identity-agent-core/conversation"
	"identity-agent-core/conversationbundle"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/sandbox"
	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// A conversation is exported as one bundle that proves it offline.
//
// The bundle carries every entry with both signatures and its words, the key
// logs of every identity that signed any part of it, the credentials each
// entry rests on with their whole transaction logs as kept, the stretch of the
// governance log the conversation was recorded in, and every anchor. Verify,
// in conversationbundle, checks it with nothing else; cmd/verify-conversation
// runs that check from the command line.
//
// Only the owner and the machines the owner authorised may export, and the
// export is written to the governance log before the bundle is made, so the
// bundle carries the row that records it. The record is anchored first, so as
// little as possible is left after the last anchor.
//
// An export never leaves anything out to succeed. Words missing from the
// record store, or no longer matching the digest the record holds, a
// credential whose log cannot be shown, a key log that cannot be had: each
// fails the export and says which, because a bundle missing any of them could
// not prove what it claims to.

// errExportIncomplete is an export that could not gather everything a bundle
// needs.
var errExportIncomplete = errors.New("the conversation cannot be exported in full")

func (s *CoreServer) handleExportConversation(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	if s.SandboxManager == nil || s.SandboxManager.Store() == nil {
		jsonError(w, "an export is written to the governance log, and there is none here", http.StatusServiceUnavailable)
		return
	}
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	c, err := store.Get(chi.URLParam(r, "cid"))
	if err != nil {
		jsonError(w, "no such conversation", http.StatusNotFound)
		return
	}
	who := "owner"
	if g, ok := TheControllerThatAsked(r); ok {
		who = g.ControllerAID
	}
	cc := sandbox.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r), Transport: "controller",
		CallerAID: who, WorkItem: c.ID, Reason: "export conversation " + c.ID}
	row := s.SandboxManager.RecordGovernanceEvent(cc, "agent.conversation.export", "ok")
	exportedAt, err := rowTime(s.SandboxManager.Store(), row)
	if row == 0 || err != nil {
		jsonError(w, "the export could not be written to the governance log, so it was not made", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.anchorRecord(); err != nil && !errors.Is(err, errKeyElsewhere) {
		log.Printf("[record] anchoring before exporting %s: %v", c.ID, err)
	}
	b, err := s.exportConversation(r.Context(), store, c, who, exportedAt)
	if err != nil {
		cc.Reason = clampWhy("export of " + c.ID + " failed: " + err.Error())
		s.SandboxManager.RecordGovernanceEvent(cc, "agent.conversation.export", "error")
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.bundle.json"`, c.ID))
	writeJSONStatus(w, http.StatusOK, b)
}

// exportConversation gathers the bundle for one conversation, exported by who
// at the time the governance log recorded it.
func (s *CoreServer) exportConversation(ctx context.Context, store *conversation.Store, c conversation.Conversation, who, at string) (*conversationbundle.Bundle, error) {
	incomplete := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errExportIncomplete, fmt.Sprintf(format, args...))
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil, incomplete("this Identity Agent has no identity")
	}
	b := &conversationbundle.Bundle{
		Format: conversationbundle.Format, Conversation: c.ID, Root: identity.AID,
		ExportedAt: at, ExportedBy: who,
	}

	// The entries, each with its words, checked against the digest the record
	// holds before they are handed out.
	entries, err := store.Entries(c.ID, 0)
	if err != nil {
		return nil, err
	}
	agents := map[string]bool{}
	countersigners := map[string]bool{}
	credentials := map[string]bool{}
	for _, e := range entries {
		body, err := store.Contents().Get(ctx, e.ContentRef)
		if err != nil {
			return nil, incomplete("the words of message %s cannot be had from the record store (%s): %v", e.MessageID, store.Contents().Kind(), err)
		}
		if agentmessage.HashBody(body) != e.BodyHash {
			return nil, incomplete("the words the record store holds for message %s are not the words it was signed over", e.MessageID)
		}
		b.Entries = append(b.Entries, conversationbundle.Entry{Envelope: e.Envelope, Body: base64.StdEncoding.EncodeToString(body)})
		rec, err := agentmessage.Read(e.Envelope)
		if err != nil {
			return nil, incomplete("message %s is unreadable: %v", e.MessageID, err)
		}
		for _, party := range []string{rec.From, rec.To} {
			if _, person := agentmessage.IsPerson(party); !person && party != "" {
				agents[party] = true
			}
		}
		if _, person := agentmessage.IsPerson(rec.From); person {
			countersigners[identity.AID] = true
		} else {
			countersigners[rec.From] = true
		}
		for _, said := range []string{rec.BodyCredential, rec.GrantSAID} {
			if said != "" {
				credentials[said] = true
			}
		}
		if rec.ControllerProof != nil && rec.ControllerProof.ControllerGrant != "" {
			credentials[rec.ControllerProof.ControllerGrant] = true
		}
	}

	// The messaging keys every entry was countersigned with.
	for _, aid := range sortedKeys(countersigners) {
		_, did, err := s.messagingKeys(aid)
		if err != nil {
			return nil, incomplete("the messaging keys of %s: %v", aid, err)
		}
		b.Countersigners = append(b.Countersigners, *did)
	}

	// The credentials, and every Controller Grant one names as having
	// authorised it, with their registries and logs.
	if err := s.exportCredentials(b, credentials); err != nil {
		return nil, err
	}

	// The key logs: the root, every AI agent, the record identity, the log's
	// signer.
	rootLog, err := s.exportKeyLog(identity.AID, nil)
	if err != nil {
		return nil, err
	}
	b.KeyLogs = append(b.KeyLogs, rootLog)
	for _, aid := range sortedKeys(agents) {
		seed, err := s.agentSeed(aid)
		if err != nil {
			return nil, incomplete("the key log of AI agent %s: %v", aid, err)
		}
		kl, err := s.exportKeyLog(aid, seed)
		if err != nil {
			return nil, err
		}
		b.KeyLogs = append(b.KeyLogs, kl)
	}
	if err := s.exportAnchors(b); err != nil {
		return nil, err
	}

	// The stretch of the governance log, and its signer's key log.
	logStore := s.SandboxManager.Store()
	first, ok, err := logStore.FirstRowFor(c.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, incomplete("the governance log holds no row for this conversation")
	}
	head, _, err := logStore.Head()
	if err != nil {
		return nil, err
	}
	if b.Log.Rows, err = logStore.StoredRows(first, head); err != nil {
		return nil, err
	}
	signer, err := s.exportLogSigner()
	if err != nil {
		return nil, err
	}
	b.Log.Signer = signer.AID
	b.KeyLogs = append(b.KeyLogs, signer)
	return b, nil
}

// exportAnchors adds the record identity's key log and every statement its
// interactions seal, read under the anchoring lock so the two agree: an
// anchoring part way through would leave an interaction without its statement.
func (s *CoreServer) exportAnchors(b *conversationbundle.Bundle) error {
	s.record.mu.Lock()
	defer s.record.mu.Unlock()
	rec, ok := s.loadRecordIdentity()
	if !ok || rec.Pending {
		return nil
	}
	kl, err := s.exportKeyLog(rec.AID, nil)
	if err != nil {
		return err
	}
	anchors, err := s.DataStore.GetRecordAnchors()
	if err != nil {
		return err
	}
	b.RecordIdentity = rec.AID
	b.KeyLogs = append(b.KeyLogs, kl)
	for _, a := range anchors {
		b.Anchors = append(b.Anchors, conversationbundle.Anchor{Seq: a.Seq, Statement: a.Statement})
	}
	return nil
}

// exportCredentials adds each credential named, and every Controller Grant
// those name as having authorised them, with their logs and registries.
func (s *CoreServer) exportCredentials(b *conversationbundle.Bundle, named map[string]bool) error {
	incomplete := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errExportIncomplete, fmt.Sprintf(format, args...))
	}
	registries := map[string]bool{}
	done := map[string]bool{}
	queue := sortedKeys(named)
	ownerSigned := false
	for len(queue) > 0 {
		said := queue[0]
		queue = queue[1:]
		if done[said] {
			continue
		}
		done[said] = true
		rec, err := s.DataStore.GetCredential(said)
		if err != nil || rec == nil {
			return incomplete("credential %s is not on record", said)
		}
		raw, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
		if err != nil {
			return incomplete("credential %s is unreadable", said)
		}
		events, _, err := s.credentialLog(rec.RegistrySAID, said)
		if err != nil {
			return incomplete("the log of credential %s: %v", said, err)
		}
		bc := conversationbundle.Credential{SAID: said, Raw: rec.AcdcJson, Log: events}
		if body, has, err := s.DataStore.GetCredentialRequestBody(said); err == nil && has {
			bc.RequestBody = &body
		}
		b.Credentials = append(b.Credentials, bc)
		registries[rec.RegistrySAID] = true
		var acdc struct {
			A struct {
				Request struct {
					Kind string `json:"kind"`
				} `json:"request"`
			} `json:"a"`
			E struct {
				AuthorisedBy struct {
					N string `json:"n"`
				} `json:"authorised_by"`
			} `json:"e"`
		}
		_ = json.Unmarshal(raw, &acdc)
		if g := acdc.E.AuthorisedBy.N; g != "" {
			queue = append(queue, g)
		}
		ownerSigned = ownerSigned || acdc.A.Request.Kind == "owner"
	}
	for _, said := range sortedKeys(registries) {
		reg, err := s.DataStore.GetRegistry(said)
		if err != nil || reg == nil || reg.VcpRawB64 == "" {
			return incomplete("the inception of registry %s was not kept", said)
		}
		b.Registries = append(b.Registries, conversationbundle.Registry{SAID: said, Inception: reg.VcpRawB64})
	}
	if ownerSigned {
		oa, err := s.ownerAuthority()
		if err != nil || oa == nil {
			return incomplete("a credential rests on the owner's signed request, and the owner is not known")
		}
		b.Owner = &conversationbundle.Owner{AID: oa.AID, Key: oa.PublicKey}
	}
	return nil
}

// exportKeyLog is an identity's key log as published, with the witness
// receipts held for each event. It is read from what is kept, signed; where
// only the engine holds it, unsigned, each event is signed by the key in force
// for it with seed, which must be that key — a key log that cannot be shown
// signed is not exported.
func (s *CoreServer) exportKeyLog(aid string, seed []byte) (conversationbundle.KeyLog, error) {
	kl := conversationbundle.KeyLog{AID: aid}
	var raws [][]byte
	var sigs []string
	if events, err := s.DataStore.GetEvents(aid); err == nil && len(events) > 0 {
		for _, ev := range events {
			raw, err := base64.StdEncoding.DecodeString(ev.RawBytesB64)
			if err != nil || len(raw) == 0 {
				return kl, fmt.Errorf("%w: event %d of %s was not kept as published", errExportIncomplete, ev.SequenceNumber, aid)
			}
			raws = append(raws, raw)
			sigs = append(sigs, ev.CesrSignature)
		}
	} else if engine, ok := s.KeriDriver.(kelHolder); ok {
		held, err := engine.GetKelByAID(aid)
		if err != nil || len(held.RawEventsB64) == 0 {
			return kl, fmt.Errorf("%w: the key log of %s is not held here", errExportIncomplete, aid)
		}
		for _, r := range held.RawEventsB64 {
			raw, err := base64.StdEncoding.DecodeString(r)
			if err != nil || len(raw) == 0 {
				return kl, fmt.Errorf("%w: the key log of %s is not held as published", errExportIncomplete, aid)
			}
			raws = append(raws, raw)
			sigs = append(sigs, "")
		}
	} else {
		return kl, fmt.Errorf("%w: the key log of %s is not held here", errExportIncomplete, aid)
	}
	if err := signWhereUnsigned(aid, raws, sigs, seed); err != nil {
		return kl, err
	}
	for i, raw := range raws {
		ev := conversationbundle.Event{Raw: base64.StdEncoding.EncodeToString(raw), Signature: sigs[i]}
		if parsed, err := keri.ParseEvent(raw); err == nil {
			if receipts, err := s.DataStore.GetWitnessReceipts(parsed.SAID); err == nil {
				for _, rc := range receipts {
					ev.Receipts = append(ev.Receipts, conversationbundle.Receipt{Witness: rc.WitnessAID, Signature: rc.CesrSignature})
				}
			}
		}
		kl.Events = append(kl.Events, ev)
	}
	return kl, nil
}

// signWhereUnsigned signs each unsigned event with seed, where seed is the key
// that event is signed by, and refuses where it is not.
func signWhereUnsigned(aid string, raws [][]byte, sigs []string, seed []byte) error {
	current := ""
	pub := ""
	if seed != nil {
		pub = iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	for i, raw := range raws {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return fmt.Errorf("%w: event %d of %s does not parse", errExportIncomplete, i, aid)
		}
		if ev.Establishment() && len(ev.Keys) > 0 {
			current = ev.Keys[0]
		}
		if sigs[i] != "" {
			continue
		}
		if pub == "" || current != pub {
			return fmt.Errorf("%w: event %d of %s carries no signature, and its key is not held here to sign it", errExportIncomplete, i, aid)
		}
		if sigs[i], err = signEventBytes(raw, seed); err != nil {
			return err
		}
	}
	return nil
}

// agentSeed is the signing key this Identity Agent holds for one of its AI
// agents.
func (s *CoreServer) agentSeed(aid string) ([]byte, error) {
	ref := s.findAgentAssetByAID(aid)
	if ref == nil {
		return nil, fmt.Errorf("%s is not an AI agent here", aid)
	}
	a, ok := s.aiAgentAsset(ref.ID)
	if !ok {
		return nil, fmt.Errorf("%s is not an AI agent here", aid)
	}
	return asset.AssetSigningSeed(s.DataDir, a.SigningIndex)
}

// exportLogSigner is the key log of the identity that signs the governance
// log. Where the engine no longer holds it, it is made again from the keys the
// signer was made from: its inception names nothing but them, so the same
// keys give the same identifier, which is checked.
func (s *CoreServer) exportLogSigner() (conversationbundle.KeyLog, error) {
	rec, found, err := readInvocationSignerRecord(s.DataDir)
	if err != nil || !found {
		return conversationbundle.KeyLog{}, fmt.Errorf("%w: this Identity Agent has no log signer on record", errExportIncomplete)
	}
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return conversationbundle.KeyLog{}, fmt.Errorf("%w: the log signer's key cannot be had: %v", errExportIncomplete, err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, rec.Index, 0)
	if err != nil {
		return conversationbundle.KeyLog{}, err
	}
	if engine, ok := s.KeriDriver.(kelHolder); ok {
		if held, err := engine.GetKelByAID(rec.AID); err == nil && len(held.RawEventsB64) > 0 {
			return s.exportKeyLog(rec.AID, seed)
		}
	}
	next, err := backup.DerivePairwiseSeed(rootSeed, rec.Index, 1)
	if err != nil {
		return conversationbundle.KeyLog{}, err
	}
	pub := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	nextPub := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(next).Public().(ed25519.PublicKey))
	raw, err := keriengine.InceptionOf(pub, nextPub)
	if err != nil {
		return conversationbundle.KeyLog{}, err
	}
	if ev, err := keri.ParseEvent(raw); err != nil || ev.Identifier != rec.AID {
		return conversationbundle.KeyLog{}, fmt.Errorf("%w: the log signer's keys do not make the identity on record", errExportIncomplete)
	}
	sig, err := signEventBytes(raw, seed)
	if err != nil {
		return conversationbundle.KeyLog{}, err
	}
	return conversationbundle.KeyLog{AID: rec.AID, Events: []conversationbundle.Event{{
		Raw: base64.StdEncoding.EncodeToString(raw), Signature: sig,
	}}}, nil
}

// rowTime is the time the governance log recorded on one of its rows.
func rowTime(log *sandbox.SandboxStore, id int64) (string, error) {
	rows, err := log.StoredRows(id, id)
	if err != nil || len(rows) != 1 {
		return "", fmt.Errorf("row %d of the governance log cannot be read back", id)
	}
	var ev struct {
		TS string `json:"ts"`
	}
	if err := json.Unmarshal([]byte(rows[0].Record), &ev); err != nil || ev.TS == "" {
		return "", fmt.Errorf("row %d of the governance log states no time", id)
	}
	return ev.TS, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
