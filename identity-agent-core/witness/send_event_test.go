package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"identity-agent-core/login"
)

// An event sent to a witness is answered with a receipt that verifies at its
// place, or Held, or an error a caller can tell apart without reading its text:
// a witness that holds no log for the identifier is ErrNotWitnessing, and a
// receipt that is not the asked witness's is ErrNoReceipt.
func TestAnEventSentToAWitnessIsAnsweredInTypes(t *testing.T) {
	d := newDelegation(t)
	sender, _ := testService(t)
	var answer func(aid string, raw []byte, sig string) (map[string]interface{}, error)
	sender.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		var req struct {
			AID   string `json:"aid"`
			Event string `json:"event_b64"`
			Sig   string `json:"cesr_signature"`
		}
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req.Event)
		return answer(req.AID, raw, req.Sig)
	}
	raw, _ := base64.StdEncoding.DecodeString(d.icpB64)
	sig, _ := login.SignString(string(raw), d.orgSeed)
	e := SignedEvent{RawBytesB64: d.icpB64, CesrSignature: sig}

	answer = func(aid string, raw []byte, sig string) (map[string]interface{}, error) {
		return d.w.ReceiveEvent(aid, raw, sig)
	}
	got, err := sender.SendEventToWitness(context.Background(), "https://w.example/", d.wkey, d.org, e, nil)
	if err != nil || got.Held || got.Receipt == "" {
		t.Fatalf("a receipt that verifies was not given: %+v %v", got, err)
	}
	if _, err := sender.SendEventToWitness(context.Background(), "https://w.example/", "BSomeOtherWitnessxxxxxxxxxxxxxxxxxxxxxxxxxxxx", d.org, e, nil); !errors.Is(err, ErrNoReceipt) {
		t.Fatalf("another witness's receipt was taken for the asked one's: %v", err)
	}
	answer = func(string, []byte, string) (map[string]interface{}, error) {
		return nil, &witnessRefusal{status: 403, body: `{"error":"not_witnessing"}`}
	}
	if _, err := sender.SendEventToWitness(context.Background(), "https://w.example/", d.wkey, d.org, e, nil); !errors.Is(err, ErrNotWitnessing) {
		t.Fatalf("a witness that holds no log was not told apart: %v", err)
	}
	answer = func(string, []byte, string) (map[string]interface{}, error) {
		return nil, &witnessRefusal{status: 409, body: `{"error":"sequence_gap"}`}
	}
	if _, err := sender.SendEventToWitness(context.Background(), "https://w.example/", d.wkey, d.org, e, nil); err == nil || errors.Is(err, ErrNotWitnessing) {
		t.Fatalf("another refusal was taken for not witnessing: %v", err)
	}
	answer = func(string, []byte, string) (map[string]interface{}, error) {
		return map[string]interface{}{"held": true, "receipted": false}, nil
	}
	if got, err := sender.SendEventToWitness(context.Background(), "https://w.example/", d.wkey, d.org, e, nil); err != nil || !got.Held || got.Receipt != "" {
		t.Fatalf("an event held from before the witness was named was not said to be: %+v %v", got, err)
	}
	if _, err := sender.SendEventToWitness(context.Background(), "https://w.example/", d.wkey, d.org, SignedEvent{RawBytesB64: d.icpB64}, nil); err == nil {
		t.Fatal("an unsigned event was sent")
	}
}
