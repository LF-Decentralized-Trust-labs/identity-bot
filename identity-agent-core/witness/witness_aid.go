package witness

import "fmt"

// witnessAID reports the identifier this agent witnesses under.
//
// A thin wrapper so the several callers that need the identifier do not each
// have to handle the hook being unset. Unset is not an error state to paper
// over: an agent with no witnessing key cannot witness, cannot be designated,
// and has nothing to publish.
func (s *Service) witnessAID() (string, error) {
	if s == nil || s.OurWitnessAID == nil {
		return "", fmt.Errorf("this agent has no witnessing key, so it has no identifier to " +
			"witness under")
	}
	return s.OurWitnessAID()
}
