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
func (s *Service) SubmitToWitness(ctx context.Context, witnessURL, signerAID string, rawEvent []byte, cesrSig string) (map[string]interface{}, error) {
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

	body, err := json.Marshal(map[string]interface{}{
		"aid":            signerAID,
		"event_b64":      base64.StdEncoding.EncodeToString(rawEvent),
		"cesr_signature": cesrSig,
	})
	if err != nil {
		return nil, err
	}
	resp, err := s.PostEvent(ctx, witnessURL, body)
	if err != nil {
		return nil, err
	}
	// Checked, not assumed. A reply that does not carry a receipt covering this
	// event is a witness that has not witnessed, whatever its status code said.
	sig, wit, err := receiptFromResponse(resp, said)
	if err != nil {
		return nil, err
	}
	s.onReceipt(said, wit, sig)
	return resp, nil
}
