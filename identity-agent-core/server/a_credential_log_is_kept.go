package server

import (
	"encoding/base64"
	"fmt"
	"log"
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

// keepCredentialEvent keeps one issuance or revocation of a credential in
// registrySAID. The bytes are checked first: an event that does not verify, or
// is about another credential or registry, is refused rather than kept as
// proof of something it does not show.
func (s *CoreServer) keepCredentialEvent(registrySAID, acdcSAID, rawB64 string) error {
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return fmt.Errorf("the transaction-log event for %s is not readable: %w", acdcSAID, err)
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		return fmt.Errorf("the transaction-log event for %s does not verify: %w", acdcSAID, err)
	}
	if ev.Subject != acdcSAID || ev.Registry != registrySAID {
		return fmt.Errorf("the transaction-log event %s is about %s in %s, not %s in %s",
			ev.SAID, ev.Subject, ev.Registry, acdcSAID, registrySAID)
	}
	return s.DataStore.AppendCredentialTELEvent(store.CredentialTELEvent{
		RegistrySAID: registrySAID,
		AcdcSAID:     acdcSAID,
		Seq:          ev.SN,
		SAID:         ev.SAID,
		Kind:         ev.Ilk,
		RawB64:       rawB64,
		RecordedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// credentialLog is the transaction log of a credential this identity issued,
// as published and in order, with the state it leaves the credential in
// ("issued" or "revoked"). The log is checked with keri-go before it is
// returned, so a gap or a broken chain is an error here, not a surprise for
// whoever is handed it.
//
// A credential with no kept log is an error, never "still valid": it was
// issued before logs were kept, or by something that did not keep one, and
// nothing here can say whether it was revoked since.
func (s *CoreServer) credentialLog(registrySAID, acdcSAID string) ([]string, string, error) {
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
	return out, status, nil
}

// keepOrSay keeps a credential's event and, when it cannot, says so loudly. The
// event has already been anchored in the issuer's key log by then, so failing
// the issue or revocation would leave the caller believing it did not happen
// when it did; and retrying a revocation would build a second one. The cost of
// a failure here is that this event cannot be handed to a verifier, which
// credentialLog then reports.
func (s *CoreServer) keepOrSay(registrySAID, acdcSAID, rawB64, what string) {
	if err := s.keepCredentialEvent(registrySAID, acdcSAID, rawB64); err != nil {
		log.Printf("[credential] the %s of %s was made but its log event could not be kept, "+
			"so it cannot be proved to a verifier: %v", what, acdcSAID, err)
	}
}
