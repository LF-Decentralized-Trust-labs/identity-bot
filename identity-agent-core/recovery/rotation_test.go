package recovery

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestRotationMandatoryBeforeActivate(t *testing.T) {
	svc := NewService(t.TempDir(), nil, nil)
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }

	archive := buildTestArchive(t, testMnemonic, nil)
	sess, err := svc.Start(StartRequest{
		ArchiveB64: encodeB64(archive),
		Mnemonic:   testMnemonic,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Activate(sess.ID)
	if err == nil {
		t.Fatal("activate without rotation must fail")
	}
	if _, ok := err.(*ErrRotationMandatory); !ok {
		t.Fatalf("expected ErrRotationMandatory, got %T: %v", err, err)
	}
}

func TestActivateAfterRotationWhenWindowElapsed(t *testing.T) {
	svc := NewService(t.TempDir(), nil, nil)
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }

	archive := buildTestArchive(t, testMnemonic, nil)
	sess, err := svc.Start(StartRequest{
		ArchiveB64: encodeB64(archive),
		Mnemonic:   testMnemonic,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.RecordRotation(sess.ID, RotationResult{
		AID:            "EtestRecoveryAID",
		NewPublicKey:   "newpub",
		SequenceNumber: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	activated, err := svc.Activate(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if activated.State != SessionActivated {
		t.Fatalf("state %s", activated.State)
	}
}

func TestCancelWindowBlocksActivate(t *testing.T) {
	svc := NewService(t.TempDir(), nil, nil)
	archive := buildTestArchive(t, testMnemonic, nil)
	sess, err := svc.Start(StartRequest{
		ArchiveB64: encodeB64(archive),
		Mnemonic:   testMnemonic,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.RecordRotation(sess.ID, RotationResult{AID: "EtestRecoveryAID", NewPublicKey: "x", SequenceNumber: 1})

	_, err = svc.Activate(sess.ID)
	if err == nil {
		t.Fatal("activate during cancel window must fail")
	}
	if _, ok := err.(*ErrCancelWindowActive); !ok {
		t.Fatalf("expected ErrCancelWindowActive, got %T: %v", err, err)
	}
}

func TestCancelWindowMinimum24Hours(t *testing.T) {
	gate := NewCancelWindowGate(NewStubAuthProviderGate())
	start := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	complete, window, _, err := gate.Schedule(start)
	if err != nil {
		t.Fatal(err)
	}
	if window < MinCancelWindow {
		t.Fatalf("window %s below minimum", window)
	}
	if complete.Sub(start) < MinCancelWindow {
		t.Fatalf("complete-after %s too soon", complete.Sub(start))
	}
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
