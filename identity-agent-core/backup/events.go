package backup

// EventReason identifies why a debounced backup was scheduled.
type EventReason string

const (
	EventKeyRotation     EventReason = "event_key_rotation"
	EventCredential      EventReason = "event_credential"
	EventContactVerified EventReason = "event_contact_verified"
	EventProfileChange   EventReason = "event_profile_change"
	EventManual          EventReason = "manual_trigger"
)