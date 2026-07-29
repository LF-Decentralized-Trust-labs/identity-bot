package didcomm

// Payload type constants. The router dispatches on `type`; it does not interpret
// `body`. Adding a type is additive and never changes the envelope shape. The /agent/*
// namespace is distinct so policy / audit can scope AI-agent traffic separately from
// human comms.
const (
	TypeCredentialOffer    = "credential-offer"
	TypeCredentialRequest  = "credential-request"
	TypeCredentialIssuance = "credential-issuance"
	TypeKeriEvent          = "keri-event"
	TypeContactRequest     = "contact-request"
	TypeDirectMessage      = "direct-message"
	TypeAck                = "ack"

	// AI-agent namespace.
	TypeAgentMessage = "agent-message"
	TypeAgentTask    = "agent-task"
	TypeAgentResult  = "agent-result"
)

var knownTypes = map[string]bool{
	TypeCredentialOffer:    true,
	TypeCredentialRequest:  true,
	TypeCredentialIssuance: true,
	TypeKeriEvent:          true,
	TypeContactRequest:     true,
	TypeDirectMessage:      true,
	TypeAck:                true,
	TypeAgentMessage:       true,
	TypeAgentTask:          true,
	TypeAgentResult:        true,
}

// KnownType reports whether t is a registered payload type (E-8).
func KnownType(t string) bool { return knownTypes[t] }

// AckRequiredFor reports whether a type requires a signed ACK by default.
func AckRequiredFor(t string) bool {
	switch t {
	case TypeCredentialIssuance, TypeKeriEvent, TypeCredentialRequest:
		return true
	default:
		return false
	}
}
