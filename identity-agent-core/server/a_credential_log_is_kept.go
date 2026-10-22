package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"sync"
	"time"

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
// or revoked that cannot be proved. The engine has already made the event in
// memory by then and is not told to forget it; the stored log, which is what
// the engine is rebuilt from and what a verifier is handed, holds neither.

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
	registrySAID, acdcSAID, rawB64, issuer string, ixn map[string]interface{}, ixnRawB64 string, sn int,
) error {
	kept, ev, err := credentialEvent(registrySAID, acdcSAID, rawB64)
	if err != nil {
		return err
	}
	if err := anchorsEvent(ixnRawB64, acdcSAID, ev); err != nil {
		return err
	}
	anchor, err := s.ownInteractionRecord(issuer, ixn, ixnRawB64, sn, "")
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

// everyAnchorIsKept matches the seals of acdcSAID in the issuer's key log one
// for one against the kept events. A seal with no kept event is a revocation
// (or issuance) the log is missing; a kept event with no seal was never
// published.
func (s *CoreServer) everyAnchorIsKept(issuerAID, acdcSAID string, kept []store.CredentialTELEvent) error {
	records, err := s.DataStore.GetEvents(issuerAID)
	if err != nil {
		return fmt.Errorf("the issuer's key log could not be read: %w", err)
	}
	anchored := map[int]string{}
	for _, rec := range records {
		raw, err := base64.StdEncoding.DecodeString(rec.RawBytesB64)
		if err != nil || len(raw) == 0 {
			continue
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
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
// one revocation, not two that the log can hold only one of.
var credentialLocks sync.Map

func lockCredential(said string) func() {
	m, _ := credentialLocks.LoadOrStore(said, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
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
