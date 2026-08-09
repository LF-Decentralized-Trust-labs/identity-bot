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
	// TypeNotification is something an agent needs to tell a person: a warning,
	// a deadline, a state change they did not ask about. Distinct from
	// direct-message, which is one person writing to another — this is a system
	// speaking, and a client presents the two differently.
	TypeNotification = "notification"

	// AI-agent namespace.
	TypeAgentMessage = "agent-message"
	TypeAgentTask    = "agent-task"
	TypeAgentResult  = "agent-result"

	// An ordinary API request and its answer, carried inside an envelope so
	// that nothing between the two agents can read either one. The router does
	// not dispatch these — the transport handles them before dispatch — but
	// they are registered here because every type crossing the envelope layer
	// must be, and one that is not is rejected on unpack.
	TypeSealedRequest  = "sealed-request"
	TypeSealedResponse = "sealed-response"
)

var knownTypes = map[string]bool{
	TypeCredentialOffer:    true,
	TypeCredentialRequest:  true,
	TypeCredentialIssuance: true,
	TypeKeriEvent:          true,
	TypeContactRequest:     true,
	TypeDirectMessage:      true,
	TypeAck:                true,
	TypeNotification:       true,
	TypeAgentMessage:       true,
	TypeAgentTask:          true,
	TypeAgentResult:        true,
	TypeSealedRequest:      true,
	TypeSealedResponse:     true,
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

