package agentbody

// The states of a machine's request to be an AI agent's body, as the
// Identity Agent reports them to the machine, which acts on them: it waits
// while pending, runs once active, and stops for good when rejected, revoked
// or expired.
const (
	StatePending  = "pending"
	StateActive   = "active"
	StateRejected = "rejected"
	StateRevoked  = "revoked"
	// StateExpired is a request nobody decided on before its enrolment string
	// ran out. It cannot be approved: an attacker who won the race for a leaked
	// string must not be able to wait for a mistaken approval.
	StateExpired = "expired"
)
