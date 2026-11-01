package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A credential this identity issues into a registry has a transaction log: its
// issuance, and later perhaps its revocation. That log is the only proof of
// whether the credential was in force at a given moment, so it is what an
// export hands a verifier, and it has to outlive the process. The engine holds
// it only in memory, so every event is kept here, as the bytes it was published
// as, at the moment it is made. Re-serialising an event later would not do: a
// different field order digests to a different identifier and chains to
// nothing.
//
// An event is kept together with the key-log interaction that anchors it, in
// one transaction, before the issuance or revocation is reported as done. If
// that fails, the issuance or revocation fails: nothing is recorded as issued
// or revoked that cannot be proved.
//
// The keeping happens inside the engine, before it appends either event to
// what it holds (drivers.TELCommitter), so a failure leaves the engine exactly
// where the store is. Were the engine to append first, its next event would
// chain to one the store never kept, and the stored key log would have a gap
// that stops it ever being loaded again.

// credentialEvent checks one issuance or revocation of a credential in
// registrySAID and returns it in the form it is kept. An event that does not
// verify, or is about another credential or registry, is refused rather than
// kept as proof of something it does not show.
func credentialEvent(registrySAID, acdcSAID, rawB64 string) (store.CredentialTELEvent, *keri.TELEvent, error) {
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return store.CredentialTELEvent{}, nil, fmt.Errorf("the transaction-log event for %s is not readable: %w", acdcSAID, err)
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		return store.CredentialTELEvent{}, nil, fmt.Errorf("the transaction-log event for %s does not verify: %w", acdcSAID, err)
	}
	if ev.Subject != acdcSAID || ev.Registry != registrySAID {
		return store.CredentialTELEvent{}, nil, fmt.Errorf("the transaction-log event %s is about %s in %s, not %s in %s",
			ev.SAID, ev.Subject, ev.Registry, acdcSAID, registrySAID)
	}
	return store.CredentialTELEvent{
		RegistrySAID: registrySAID,
		AcdcSAID:     acdcSAID,
		Seq:          ev.SN,
		SAID:         ev.SAID,
		Kind:         ev.Ilk,
		RawB64:       rawB64,
		RecordedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}, ev, nil
}

// engineKeepsCredentialLogs installs keepTELCommit in an engine that can keep
// registry events before appending them, and reports whether it could. An
// engine that cannot has each event kept after it returns.
func (s *CoreServer) engineKeepsCredentialLogs() bool {
	s.engineSigns()
	c, ok := s.KeriDriver.(drivers.TELCommitter)
	if ok {
		c.SetTELCommit(s.keepTELCommit)
	}
	return ok
}

// keepTELCommit keeps a registry inception, issuance or revocation with the
// key-log interaction that anchors it, checked, in one transaction.
func (s *CoreServer) keepTELCommit(c drivers.TELCommit) error {
	ev, err := keri.VerifyTELEvent(c.TELRaw)
	if err != nil {
		return fmt.Errorf("the transaction-log event does not verify: %w", err)
	}
	var ixn map[string]interface{}
	if err := json.Unmarshal(c.KELRaw, &ixn); err != nil {
		return fmt.Errorf("the anchoring event does not parse: %w", err)
	}
	telB64, kelB64 := base64.StdEncoding.EncodeToString(c.TELRaw), base64.StdEncoding.EncodeToString(c.KELRaw)
	if ev.Ilk != "vcp" {
		return s.keepAnchoredCredentialEvent(ev.Registry, ev.Subject, telB64, c.AID, ixn, kelB64, c.SN, c.Signature)
	}
	if err := checkRegistryInception(telB64, ev.Subject, kelB64); err != nil {
		return err
	}
	// Signed by the identity's key, as the engine checked.
	anchor, err := s.ownInteractionRecord(c.AID, ixn, kelB64, c.SN, c.Signature)
	if err != nil {
		return fmt.Errorf("the registry's anchor could not be kept: %w", err)
	}
	return s.DataStore.KeepRegistry(store.CredentialRegistry{
		RegistrySAID: ev.Subject,
		IssuerAID:    c.AID,
		VcpJson:      string(c.TELRaw),
		VcpRawB64:    telB64,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}, &anchor)
}

// keepAfter keeps what an engine without TELCommitter has just made.
func (s *CoreServer) keepAfter(aid string, sn int, kelB64, telB64 string) error {
	kel, err := base64.StdEncoding.DecodeString(kelB64)
	if err != nil {
		return err
	}
	tel, err := base64.StdEncoding.DecodeString(telB64)
	if err != nil {
		return err
	}
	return s.keepTELCommit(drivers.TELCommit{AID: aid, SN: sn, KELRaw: kel, TELRaw: tel})
}

// keepCredentialEvent keeps one checked event of a credential's log on its own.
func (s *CoreServer) keepCredentialEvent(registrySAID, acdcSAID, rawB64 string) error {
	kept, _, err := credentialEvent(registrySAID, acdcSAID, rawB64)
	if err != nil {
		return err
	}
	return s.DataStore.AppendCredentialTELEvent(kept)
}

// keepAnchoredCredentialEvent keeps a credential's event and the interaction in
// the issuer's key log that anchors it, together or not at all. The
// interaction must carry the seal of exactly this event, or the pair would be
// kept as proof of each other when it is not.
func (s *CoreServer) keepAnchoredCredentialEvent(
	registrySAID, acdcSAID, rawB64, issuer string, ixn map[string]interface{}, ixnRawB64 string, sn int, signature string,
) error {
	kept, ev, err := credentialEvent(registrySAID, acdcSAID, rawB64)
	if err != nil {
		return err
	}
	if err := anchorsEvent(ixnRawB64, acdcSAID, ev); err != nil {
		return err
	}
	anchor, err := s.ownInteractionRecord(issuer, ixn, ixnRawB64, sn, signature)
	if err != nil {
		return err
	}
	return s.DataStore.KeepCredentialEvent(kept, &anchor)
}

// anchorsEvent reports whether a key-log event carries the seal of ev.
func anchorsEvent(ixnRawB64, subject string, ev *keri.TELEvent) error {
	raw, err := base64.StdEncoding.DecodeString(ixnRawB64)
	if err != nil {
		return fmt.Errorf("the anchoring event is not readable: %w", err)
	}
	ixn, err := keri.ParseEvent(raw)
	if err != nil {
		return fmt.Errorf("the anchoring event does not parse: %w", err)
	}
	seals, err := ixn.Seals()
	if err != nil {
		return err
	}
	for _, seal := range seals {
		if seal.Identifier == subject && seal.SAID == ev.SAID && seal.SN == uint64(ev.SN) {
			return nil
		}
	}
	return fmt.Errorf("the key-log event %s does not anchor %s %s", ixn.SAID, ev.Ilk, ev.SAID)
}

// credentialLog is the transaction log of a credential this identity issued,
// as published and in order, with the state it leaves the credential in
// ("issued" or "revoked"). It is what an export will hand a verifier; nothing
// outside this package reads it yet.
//
// It refuses rather than answer whenever the answer could be wrong:
//   - nothing is kept for the credential, because it was issued before logs
//     were kept or by something that did not keep one;
//   - the registry's own inception was not kept, so the registry cannot be
//     shown to be the issuer's;
//   - the log does not hold together as one chain (keri-go);
//   - the issuer's key log anchors an event of this credential that is not
//     kept, or a kept event is anchored nowhere;
//   - this Identity Agent recorded the credential as revoked and the log does
//     not end in a revocation.
func (s *CoreServer) credentialLog(registrySAID, acdcSAID string) ([]string, string, error) {
	reg, err := s.DataStore.GetRegistry(registrySAID)
	if err != nil {
		return nil, "", err
	}
	if reg == nil || reg.VcpRawB64 == "" {
		return nil, "", fmt.Errorf("the inception of registry %s was not kept, so no credential in it "+
			"can be shown to be its issuer's", registrySAID)
	}
	events, err := s.DataStore.GetCredentialTEL(registrySAID, acdcSAID)
	if err != nil {
		return nil, "", err
	}
	if len(events) == 0 {
		return nil, "", fmt.Errorf("no transaction log is kept for %s in %s, so whether it is "+
			"still in force cannot be shown", acdcSAID, registrySAID)
	}
	raws := make([][]byte, 0, len(events))
	out := make([]string, 0, len(events))
	for _, ev := range events {
		raw, err := base64.StdEncoding.DecodeString(ev.RawB64)
		if err != nil {
			return nil, "", fmt.Errorf("the kept event %s is not readable: %w", ev.SAID, err)
		}
		raws = append(raws, raw)
		out = append(out, ev.RawB64)
	}
	status, err := keri.CredentialStatus(acdcSAID, raws)
	if err != nil {
		return nil, "", fmt.Errorf("the kept transaction log for %s does not hold together: %w", acdcSAID, err)
	}
	if err := s.everyAnchorIsKept(reg.IssuerAID, acdcSAID, events); err != nil {
		return nil, "", err
	}
	if rec, _ := s.DataStore.GetCredential(acdcSAID); rec != nil && rec.Status == "revoked" && status != keri.StatusRevoked {
		return nil, "", fmt.Errorf("%s is recorded here as revoked but its kept log ends %q, so the "+
			"revocation cannot be proved", acdcSAID, status)
	}
	return out, status, nil
}

// everyAnchorIsKept checks the issuer's stored key log as one chain with
// keri-go, every event in sequence and naming the one before it, and then
// matches the seals of acdcSAID in it one for one against the kept events. A
// log with a gap is not the log the issuer published; a seal with no kept
// event is a revocation (or issuance) the credential's log is missing; a kept
// event with no seal was never published.
func (s *CoreServer) everyAnchorIsKept(issuerAID, acdcSAID string, kept []store.CredentialTELEvent) error {
	records, err := s.DataStore.GetEvents(issuerAID)
	if err != nil {
		return fmt.Errorf("the issuer's key log could not be read: %w", err)
	}
	raws := make([][]byte, 0, len(records))
	for _, rec := range records {
		raw, err := base64.StdEncoding.DecodeString(rec.RawBytesB64)
		if err != nil || len(raw) == 0 {
			return fmt.Errorf("event %d of the issuer's key log was not kept as published, so the "+
				"log cannot be checked", rec.SequenceNumber)
		}
		raws = append(raws, raw)
	}
	if err := keri.ValidateKEL(raws); err != nil {
		return fmt.Errorf("the issuer's stored key log does not hold together: %w", err)
	}
	anchored := map[int]string{}
	for _, raw := range raws {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return err
		}
		seals, _ := ev.Seals()
		for _, seal := range seals {
			if seal.Identifier == acdcSAID {
				anchored[int(seal.SN)] = seal.SAID
			}
		}
	}
	for _, ev := range kept {
		if said, ok := anchored[ev.Seq]; !ok || said != ev.SAID {
			return fmt.Errorf("event %d of %s's log (%s) is not anchored in the issuer's key log",
				ev.Seq, acdcSAID, ev.SAID)
		}
		delete(anchored, ev.Seq)
	}
	for sn, said := range anchored {
		return fmt.Errorf("the issuer's key log anchors event %d of %s (%s), which is not kept, so "+
			"the log handed out would leave it out", sn, acdcSAID, said)
	}
	return nil
}

// credentialLocks serialises revocations per credential, so two at once make
// one revocation, not two that the log can hold only one of. An entry lives
// only while somebody holds or waits for it.
var (
	credentialLocksMu sync.Mutex
	credentialLocks   = map[string]*credentialLock{}
)

type credentialLock struct {
	mu      sync.Mutex
	holders int
}

func lockCredential(said string) func() {
	credentialLocksMu.Lock()
	l := credentialLocks[said]
	if l == nil {
		l = &credentialLock{}
		credentialLocks[said] = l
	}
	l.holders++
	credentialLocksMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		credentialLocksMu.Lock()
		if l.holders--; l.holders == 0 {
			delete(credentialLocks, said)
		}
		credentialLocksMu.Unlock()
	}
}

// alreadyRevoked reports whether the kept log of a credential already ends in
// a revocation.
func (s *CoreServer) alreadyRevoked(registrySAID, acdcSAID string) bool {
	events, err := s.DataStore.GetCredentialTEL(registrySAID, acdcSAID)
	if err != nil || len(events) == 0 {
		return false
	}
	return events[len(events)-1].Kind == "rev"
}

// checkRegistryInception verifies a registry's inception as published, checks
// it is the registry named, and that the key-log event kept with it anchors it.
func checkRegistryInception(vcpRawB64, registrySAID, ixnRawB64 string) error {
	raw, err := base64.StdEncoding.DecodeString(vcpRawB64)
	if err != nil {
		return fmt.Errorf("the inception of registry %s is not readable: %w", registrySAID, err)
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		return fmt.Errorf("the inception of registry %s does not verify: %w", registrySAID, err)
	}
	if ev.Ilk != "vcp" || ev.Subject != registrySAID {
		return fmt.Errorf("the registry inception given is a %s of %s, not the inception of %s", ev.Ilk, ev.Subject, registrySAID)
	}
	return anchorsEvent(ixnRawB64, registrySAID, ev)
}

// noteRegistryWithoutInception says once that an issuer's registry predates
// kept inceptions, which is why a new one is made beside it.
func noteRegistryWithoutInception(reg *store.CredentialRegistry) {
	log.Printf("[credential] registry %s was made before registry inceptions were kept, so nothing "+
		"issued in it can be proved; new credentials go into a new registry", reg.RegistrySAID)
}

// engineSigns installs how the engine has the events it appends signed:
// every interaction it appends to a key log is signed by that identity's
// current key, which the engine checks, or it is not appended.
func (s *CoreServer) engineSigns() {
	if e, ok := s.KeriDriver.(interface {
		SetEventSignature(func(aid, key string, raw []byte) (string, error))
	}); ok {
		e.SetEventSignature(s.signEventFor)
	}
}

// signEventFor signs an event the engine is about to append to aid's key log:
// with the signature the device holding the key made, when it was signed
// there; with the record identity's key, for its log; with this identity's
// key, where it is held here. Anything else is not signed, so not appended.
func (s *CoreServer) signEventFor(aid, key string, raw []byte) (string, error) {
	b64 := base64.StdEncoding.EncodeToString(raw)
	if v, ok := s.signedElsewhere.Load(b64); ok {
		return v.(string), nil
	}
	if v, ok := s.eventSigners.Load(aid); ok {
		return signEventBytes(raw, v.([]byte))
	}
	if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil && identity.AID == aid {
		// The key the event names, which for a rotation is the key it
		// reveals and for an earlier event an earlier key: whichever of
		// this identity's keys this Identity Agent derives.
		seed, err := s.ownSeedForKey(key)
		if err != nil {
			return "", err
		}
		return signEventBytes(raw, seed)
	}
	// This Identity Agent's own identity being founded, before there is a
	// record of it: the founding key is the one it derives first.
	if identity, err := s.DataStore.GetIdentity(); err == nil && identity == nil {
		if seed, err := s.foundingSeedForKey(key, raw); err == nil {
			return signEventBytes(raw, seed)
		}
	}
	// One of this identity's pairwise identities, whose keys it derives.
	if seed, err := s.signingSeedForAID(aid); err == nil {
		return signEventBytes(raw, seed)
	}
	return "", fmt.Errorf("this Identity Agent holds no key for %s", aid)
}
