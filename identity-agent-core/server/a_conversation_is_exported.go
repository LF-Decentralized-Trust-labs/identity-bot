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

	"identity-agent-core/activitylog"
	"identity-agent-core/asset"
	"identity-agent-core/backup"
	"identity-agent-core/conversation"
	"identity-agent-core/conversationbundle"
	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/permission"
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
// What goes in a bundle, and the refusal to leave anything out, are
// conversationbundle.Build's: any store keeping a conversation record exports
// through it. This file is the Identity Agent's side — who may export, the
// governance row that records it, and the record it holds today.

func (s *CoreServer) handleExportConversation(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	if s.ActivityLog == nil {
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
	// The owner is named by their identity where the organisation knows it.
	who := "owner"
	if oa, err := s.ownerAuthority(); err == nil && oa != nil && oa.AID != "" {
		who = oa.AID
	}
	if g, ok := TheControllerThatAsked(r); ok {
		who = g.ControllerAID
	}
	cc := permission.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r), Transport: "controller",
		CallerAID: who, WorkItem: c.ID, Reason: "export conversation " + c.ID}
	// Anchored first, so the anchoring's own row is in the stretch the bundle
	// carries, ahead of the export's row: a bundle cannot then be handed out
	// with its anchors stripped and the log still read as whole.
	if _, err := s.anchorRecord(); err != nil && !errors.Is(err, errKeyElsewhere) {
		log.Printf("[record] anchoring before exporting %s: %v", c.ID, err)
	}
	row := s.ActivityLog.RecordGovernanceEvent(cc, "agent.conversation.export", "ok")
	exportedAt, err := rowTime(s.ActivityLog, row)
	if row == 0 || err != nil {
		jsonError(w, "the export could not be written to the governance log, so it was not made", http.StatusServiceUnavailable)
		return
	}
	b, err := s.exportConversation(r.Context(), store, c, who, exportedAt)
	if err != nil {
		cc.Reason = clampWhy("export of " + c.ID + " failed: " + err.Error())
		s.ActivityLog.RecordGovernanceEvent(cc, "agent.conversation.export", "error")
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.bundle.json"`, c.ID))
	writeJSONStatus(w, http.StatusOK, b)
}

// exportConversation gathers the bundle for one conversation, exported by who
// at the time the governance log recorded it. What a bundle carries is decided
// in conversationbundle.Build. This Identity Agent hands over the entries and
// words it holds today (the Record, which goes with the record when the record
// is kept elsewhere), and what only it can show: the anchors and governance
// log, the key logs, and the credentials.
//
// The adapters below return plain errors; Build says the bundle is incomplete.
func (s *CoreServer) exportConversation(ctx context.Context, store *conversation.Store, c conversation.Conversation, who, at string) (*conversationbundle.Bundle, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil, fmt.Errorf("%w: this Identity Agent has no identity", conversationbundle.ErrIncomplete)
	}
	// The governance log's signer, read once: the log and its signer's key
	// log are both asked for, and a failed read must say so rather than read
	// as an identity this Identity Agent does not hold.
	signer, found, err := readInvocationSignerRecord(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("%w: the governance log's signer cannot be read: %v", conversationbundle.ErrIncomplete, err)
	}
	if !found {
		return nil, fmt.Errorf("%w: this Identity Agent has no log signer on record", conversationbundle.ErrIncomplete)
	}
	return conversationbundle.Build(ctx, conversationbundle.Sources{
		Record:      exportedRecord{store: store},
		Ledger:      exportedLedger{s: s, signer: signer.AID},
		Identities:  exportedIdentities{s: s, root: identity.AID, signer: signer},
		Credentials: exportedCredentials{s: s},
	}, c.ID, identity.AID, who, at)
}

// exportedRecord is the conversation's entries and words as this Identity
// Agent holds them today.
type exportedRecord struct {
	store *conversation.Store
}

func (r exportedRecord) Entries(_ context.Context, conv string) ([]conversationbundle.RecordedEntry, error) {
	entries, err := r.store.Entries(conv, 0)
	if err != nil {
		return nil, err
	}
	out := make([]conversationbundle.RecordedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, conversationbundle.RecordedEntry{
			MessageID: e.MessageID, Envelope: e.Envelope, BodyHash: e.BodyHash, ContentRef: e.ContentRef,
		})
	}
	return out, nil
}

func (r exportedRecord) Words(ctx context.Context, e conversationbundle.RecordedEntry) ([]byte, error) {
	body, err := r.store.Contents().Get(ctx, e.ContentRef)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", r.store.Contents().Kind(), err)
	}
	return body, nil
}

// exportedLedger is this Identity Agent's account of the conversation: the
// anchors that fix the record and the governance log it was written to.
type exportedLedger struct {
	s      *CoreServer
	signer string
}

// Anchors reads the record identity's key log and every statement its
// interactions seal under the anchoring lock, so the two agree: an anchoring
// part way through would leave an interaction without its statement.
func (l exportedLedger) Anchors(context.Context) (conversationbundle.KeyLog, []conversationbundle.Anchor, bool, error) {
	s := l.s
	s.record.mu.Lock()
	defer s.record.mu.Unlock()
	rec, ok := s.loadRecordIdentity()
	if !ok || rec.Pending {
		return conversationbundle.KeyLog{}, nil, false, nil
	}
	kl, err := s.exportKeyLog(rec.AID, nil)
	if err != nil {
		return kl, nil, false, err
	}
	held, err := s.DataStore.GetRecordAnchors()
	if err != nil {
		return kl, nil, false, err
	}
	anchors := make([]conversationbundle.Anchor, 0, len(held))
	for _, a := range held {
		anchors = append(anchors, conversationbundle.Anchor{Seq: a.Seq, Statement: a.Statement})
	}
	return kl, anchors, true, nil
}

func (l exportedLedger) Log(_ context.Context, conv string) (conversationbundle.Log, error) {
	logStore := l.s.ActivityLog
	first, ok, err := logStore.FirstRowFor(conv)
	if err != nil || !ok {
		return conversationbundle.Log{Signer: l.signer}, err
	}
	head, _, err := logStore.Head()
	if err != nil {
		return conversationbundle.Log{}, err
	}
	rows, err := logStore.StoredRows(first, head)
	return conversationbundle.Log{Signer: l.signer, Rows: rows}, err
}

// exportedIdentities are the key logs this Identity Agent holds: its own, its
// AI agents', and its governance log signer's.
type exportedIdentities struct {
	s      *CoreServer
	root   string
	signer invocationSignerRecord
}

func (x exportedIdentities) KeyLog(_ context.Context, aid string) (conversationbundle.KeyLog, error) {
	if aid == x.root {
		return x.s.exportKeyLog(aid, nil)
	}
	if aid == x.signer.AID {
		return x.s.exportLogSigner(x.signer)
	}
	seed, err := x.s.agentSeed(aid)
	if err != nil {
		return conversationbundle.KeyLog{}, err
	}
	return x.s.exportKeyLog(aid, seed)
}

func (x exportedIdentities) MessagingKeys(_ context.Context, aid string) (didcomm.DID, error) {
	_, did, err := x.s.messagingKeys(aid)
	if err != nil {
		return didcomm.DID{}, err
	}
	return *did, nil
}

// exportedCredentials are the credentials this Identity Agent issued.
type exportedCredentials struct{ s *CoreServer }

func (x exportedCredentials) Credential(_ context.Context, said string) (conversationbundle.Credential, string, error) {
	rec, err := x.s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		return conversationbundle.Credential{}, "", errors.New("not on record")
	}
	events, _, err := x.s.credentialLog(rec.RegistrySAID, said)
	if err != nil {
		return conversationbundle.Credential{}, "", fmt.Errorf("its log: %v", err)
	}
	c := conversationbundle.Credential{SAID: said, Raw: rec.AcdcJson, Log: events}
	if body, has, err := x.s.DataStore.GetCredentialRequestBody(said); err == nil && has {
		c.RequestBody = &body
	}
	return c, rec.RegistrySAID, nil
}

func (x exportedCredentials) Registry(_ context.Context, said string) (conversationbundle.Registry, error) {
	reg, err := x.s.DataStore.GetRegistry(said)
	if err != nil || reg == nil || reg.VcpRawB64 == "" {
		return conversationbundle.Registry{}, errors.New("its inception was not kept")
	}
	return conversationbundle.Registry{SAID: said, Inception: reg.VcpRawB64}, nil
}

func (x exportedCredentials) Owner(context.Context) (*conversationbundle.Owner, error) {
	oa, err := x.s.ownerAuthority()
	if err != nil || oa == nil {
		return nil, errors.New("the owner is not known")
	}
	return &conversationbundle.Owner{AID: oa.AID, Key: oa.PublicKey}, nil
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
				return kl, fmt.Errorf("event %d of %s was not kept as published", ev.SequenceNumber, aid)
			}
			raws = append(raws, raw)
			sigs = append(sigs, ev.CesrSignature)
		}
	} else if engine, ok := s.KeriDriver.(drivers.KELHolder); ok {
		held, err := engine.GetKelByAID(aid)
		if err != nil || len(held.RawEventsB64) == 0 {
			return kl, fmt.Errorf("the key log of %s is not held here", aid)
		}
		for _, r := range held.RawEventsB64 {
			raw, err := base64.StdEncoding.DecodeString(r)
			if err != nil || len(raw) == 0 {
				return kl, fmt.Errorf("the key log of %s is not held as published", aid)
			}
			raws = append(raws, raw)
			sigs = append(sigs, "")
		}
	} else {
		return kl, fmt.Errorf("the key log of %s is not held here", aid)
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
			return fmt.Errorf("event %d of %s does not parse", i, aid)
		}
		if ev.Establishment() && len(ev.Keys) > 0 {
			current = ev.Keys[0]
		}
		if sigs[i] != "" {
			continue
		}
		if pub == "" || current != pub {
			return fmt.Errorf("event %d of %s carries no signature, and its key is not held here to sign it", i, aid)
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
func (s *CoreServer) exportLogSigner(rec invocationSignerRecord) (conversationbundle.KeyLog, error) {
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return conversationbundle.KeyLog{}, fmt.Errorf("the log signer's key cannot be had: %v", err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, rec.Index, 0)
	if err != nil {
		return conversationbundle.KeyLog{}, err
	}
	if engine, ok := s.KeriDriver.(drivers.KELHolder); ok {
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
		return conversationbundle.KeyLog{}, fmt.Errorf("the log signer's keys do not make the identity on record")
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
func rowTime(log *activitylog.Log, id int64) (string, error) {
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
