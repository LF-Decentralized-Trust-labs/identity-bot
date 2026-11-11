package watcher

import (
	"testing"
)

// An identity that opted out is not discussed with peers: the cross-check
// answers as it would for one never seen, revealing neither digest nor time.
func TestKelCheckHonoursOptOut(t *testing.T) {
	svc, now := checkingService(t)
	resp, _, err := svc.KelCheck(signedCheck("EHeld", 1, heldDigest, now.Unix()), checkedAt, servesHeld)
	if err != nil || !resp.Match {
		t.Fatalf("before opting out: %+v, %v", resp, err)
	}
	if err := svc.Store.SetOptOut("EHeld", true); err != nil {
		t.Fatal(err)
	}
	resp, _, err = svc.KelCheck(signedCheck("EHeld", 1, heldDigest, now.Unix()+1), checkedAt, servesHeld)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Match {
		t.Fatalf("an opted-out identity's record was revealed: %+v", resp)
	}
}
