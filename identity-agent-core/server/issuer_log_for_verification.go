package server

import (
	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// An issuer's key log is the one thing that says a credential's issuer is who
// it claims to be. There are three honest answers about it, and "checked" is
// only one: the log was read and the credential held up against it, the log
// was read and did not hold together, or no log is held here at all. The last
// is never reported as the first.
const (
	issuerChecked         = "checked"
	issuerNotCheckedFmt   = "not checked: "
	issuerNoLogHeld       = issuerNotCheckedFmt + "no key log is held for the issuer"
	issuerNoLogHeldReason = "the issuer's key log is not held here, so the credential cannot be shown to come from that issuer"
)

// issuerLogForVerification is the one place that reads an issuer's key log for
// checking a credential: a verified log held for a contact, given whole, with
// the bytes and signatures it was verified by (unwrapped to parsed fields, the
// engine can check the chain but no signature, and never reports the log as
// verified), else this agent's own log in the same form. Nil when neither is
// held.
func (s *CoreServer) issuerLogForVerification(issuerAid string) []map[string]interface{} {
	if kelRecord, err := s.DataStore.GetContactKEL(issuerAid); err == nil && kelRecord != nil && kelRecord.KelVerified && kelRecord.KEL != nil {
		return kelRecord.KEL
	}
	if ownEvents, err := s.DataStore.GetEvents(issuerAid); err == nil && len(ownEvents) > 0 {
		return ownLogForVerification(ownEvents)
	}
	return nil
}

// ownLogForVerification gives this agent's own log the way a contact's is
// kept: each event with the bytes it was serialised as and the controller's
// signature over them. A log with any event kept without its bytes (written
// before they were kept) can only be read, so it is given as parsed events and
// the engine reports it unverified rather than passing it.
func ownLogForVerification(events []store.EventRecord) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		if ev.RawBytesB64 == "" {
			return eventRecordsToKEDs(events)
		}
		out = append(out, map[string]interface{}{
			"event_json":     ev.EventJSON,
			"raw_bytes_b64":  ev.RawBytesB64,
			"cesr_signature": ev.CesrSignature,
		})
	}
	return out
}

// issuerVerdict folds what is known of the issuer's log into the engine's
// verdict. A credential whose issuer could not be checked is never verified:
// without the log nothing says the issuer is who the credential claims, and a
// forger who names an issuer nobody here knows would otherwise pass. It is
// reported as not checked, never as failed or as passed.
func issuerVerdict(res *drivers.DriverVerifyCredentialResponse, logHeld bool) (status string) {
	if res == nil {
		res = &drivers.DriverVerifyCredentialResponse{}
	}
	if logHeld {
		return issuerChecked
	}
	if res.Checks == nil {
		res.Checks = map[string]interface{}{}
	}
	res.Checks["issuer_kel"] = nil
	res.Verified = false
	res.Errors = append(res.Errors, issuerNoLogHeldReason)
	return issuerNoLogHeld
}
