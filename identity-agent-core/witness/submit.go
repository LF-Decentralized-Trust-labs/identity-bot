package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// SubmitToWitness sends one event to one witness and returns its receipt.
//
// The receipt is verified before it is returned, so a caller never holds one
// that proves nothing. Separate from BroadcastEvent because the two answer
// different questions: broadcasting asks everybody and counts, this asks one and
// reports what it said.
func (s *Service) SubmitToWitness(ctx context.Context, witnessURL, signerAID string, rawEvent []byte, cesrSigs ...string) (map[string]interface{}, error) {
	if len(rawEvent) == 0 {
		return nil, fmt.Errorf("an event cannot be submitted without the bytes it was published as")
	}
	var ked map[string]interface{}
	if err := json.Unmarshal(rawEvent, &ked); err != nil {
		return nil, fmt.Errorf("the event to submit is not readable: %w", err)
	}
	said, _ := ked["d"].(string)
	if said == "" {
		return nil, fmt.Errorf("the event carries no identifier to be receipted")
	}

	body := eventBody(signerAID, base64.StdEncoding.EncodeToString(rawEvent), cesrSigs)
	resp, err := s.PostEvent(s.ownersLocalAllowed(ctx, witnessURL), witnessURL, body)
	if err != nil {
		return nil, err
	}
	// Checked, not assumed. A reply that does not carry a receipt covering this
	// event is a witness that has not witnessed, whatever its status code said.
	designated, _ := s.designationAfter(signerAID, ked)
	// A rotation that leaves no witness in force leaves an empty list, which the hook reports as it reports a
	// log it cannot read: nil. For a rotation the list is known, and the cut witness's receipt is not in it.
	if t, _ := ked["t"].(string); designated == nil && s.DesignationAfter != nil && (t == "rot" || t == "drt") {
		designated = []string{}
	}
	sig, wit, err := receiptFromResponse(resp, rawEvent, said, designated)
	if err != nil {
		return nil, err
	}
	s.onReceipt(said, wit, sig, rawEvent, designated)
	return resp, nil
}
