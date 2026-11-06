package server

import (
	"errors"
	"log"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// keepCaughtUpKeyLog saves an issuer's key log that was caught up from its
// witnesses to the contact record, so the next check starts from it and this
// agent's own view of the issuer is no longer stale. It is forward-only, and
// the rule is the store's, not a copy of it: SaveContactKEL refuses a log that
// forks from, or does not carry on from, the verified one held
// (store.ErrLogDoesNotExtend), and the held record is left as it was. This
// function adds only that the new log must verify end to end by itself and must
// be longer than the one held, and saves nothing for an issuer that is not a
// held contact. Reports whether the record was replaced.
func (s *CoreServer) keepCaughtUpKeyLog(issuer string, kel []map[string]interface{}) bool {
	held, err := s.DataStore.GetContactKEL(issuer)
	if err != nil || held == nil || !held.KelVerified || len(kel) <= len(held.KEL) {
		return false
	}
	in, ok := drivers.ValidateKELInputFromRecords(issuer, kel)
	if !ok {
		return false
	}
	val, err := drivers.ValidateKELFromBytes(in)
	if err != nil || !val.KelVerified || val.CurrentPublicKey == "" {
		return false
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: issuer, KEL: kel, KelVerified: true, CurrentPublicKey: val.CurrentPublicKey,
		EventsValidated: val.EventsValidated, ValidatedAt: time.Now().UTC().Format(time.RFC3339),
		Witnessed: val.Witnessed,
	}); err != nil {
		if !errors.Is(err, store.ErrLogDoesNotExtend) {
			log.Printf("[verify] could not keep the caught-up key log for %s: %v", issuer, err)
		}
		return false
	}
	return true
}
