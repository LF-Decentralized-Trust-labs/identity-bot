package server

import (
	"log"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// carriesOn reports whether next is held with every event of held unchanged, in
// the same places, and at least one more after them. It compares the bytes each
// event was published as, so a log that differs anywhere in what is already
// held (a fork) does not carry on from it.
func carriesOn(held, next []map[string]interface{}) bool {
	if len(next) <= len(held) || len(held) == 0 {
		return false
	}
	for i := range held {
		a, _ := held[i]["raw_bytes_b64"].(string)
		b, _ := next[i]["raw_bytes_b64"].(string)
		if a == "" || a != b {
			return false
		}
	}
	return true
}

// keepCaughtUpKeyLog saves an issuer's key log that was caught up from its
// witnesses to the contact record, so the next check starts from it and this
// agent's own view of the issuer is no longer stale. It is forward-only: the
// record is replaced only when it is a verified log the new one carries on from
// and the new one verifies end to end by itself. A log that forks from the held
// one, or does not verify, is not saved and the held record is left as it was.
// Nothing is saved for an issuer that is not a held contact. Reports whether
// the record was replaced.
func (s *CoreServer) keepCaughtUpKeyLog(issuer string, kel []map[string]interface{}) bool {
	held, err := s.DataStore.GetContactKEL(issuer)
	if err != nil || held == nil || !held.KelVerified || !carriesOn(held.KEL, kel) {
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
		log.Printf("[verify] could not keep the caught-up key log for %s: %v", issuer, err)
		return false
	}
	return true
}
