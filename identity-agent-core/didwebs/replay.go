package didwebs

import "context"

// KELReplayBackend replays KEL events on the LOCAL engine (the contract).
type KELReplayBackend interface {
	ValidateKEL(ctx context.Context, aid string, events []map[string]interface{}) (verified bool, currentPub string, errors []string, err error)
}
