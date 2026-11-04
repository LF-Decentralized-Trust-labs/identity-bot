package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

// A pass about to conclude that a witness does not hold a log waits for the
// send in flight to it, and then believes the witness's own tip.
func TestAWitnessIsNotFoundLackingWhileASendToItIsInFlight(t *testing.T) {
	d := newDelegation(t)
	sender, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: d.wkey})
	sender.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
		_, nonce, _ := strings.Cut(url, "?nonce=")
		return d.w.KelTip(d.org, nonce)
	}
	release := make(chan struct{})
	sender.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		<-release
		var req struct {
			AID   string `json:"aid"`
			Event string `json:"event_b64"`
			Sig   string `json:"cesr_signature"`
		}
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req.Event)
		return d.w.ReceiveEvent(req.AID, raw, req.Sig)
	}
	signed := func(rawB64 string) SignedEvent {
		raw, _ := base64.StdEncoding.DecodeString(rawB64)
		sig, _ := login.SignString(string(raw), d.orgSeed)
		return SignedEvent{RawBytesB64: rawB64, CesrSignature: sig}
	}
	log := []SignedEvent{signed(d.icpB64), signed(d.approvalB64)}

	passDone := make(chan bool, 1)
	go func() { // the pass whose send to the witness is in flight
		passDone <- sender.BringUpToDate(context.Background(), d.org, log, []string{d.wkey}, 1)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !sender.sendsInFlight(d.org) {
		if time.Now().After(deadline) {
			t.Fatal("the send never began")
		}
		time.Sleep(time.Millisecond)
	}
	// Nothing is settled while it is in flight: not held, and not counted.
	short, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	held, settled := sender.HeldThrough(short, d.org, log, []string{d.wkey}, 1)
	cancel()
	if settled || held {
		t.Fatalf("concluded while a send was in flight: held=%v settled=%v", held, settled)
	}
	go func() { time.Sleep(50 * time.Millisecond); close(release) }()
	held, settled = sender.HeldThrough(context.Background(), d.org, log, []string{d.wkey}, 1)
	if !settled || !held {
		t.Fatalf("after the send completed the witness holds the log: held=%v settled=%v", held, settled)
	}
	<-passDone
}
