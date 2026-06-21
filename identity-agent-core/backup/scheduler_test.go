package backup

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerDebounce(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil)
	svc.Scheduler.SetDebounceInterval(50 * time.Millisecond)

	cfg := DefaultConfig()
	cfg.Enabled = true
	if err := svc.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	var fired int32
	svc.Scheduler.SetAfterRunHook(func(reason string) {
		atomic.AddInt32(&fired, 1)
	})

	svc.Scheduler.TriggerEvent(string(EventProfileChange))
	svc.Scheduler.TriggerEvent(string(EventCredential))
	svc.Scheduler.TriggerEvent(string(EventKeyRotation))

	time.Sleep(120 * time.Millisecond)

	if atomic.LoadInt32(&fired) != 1 {
		t.Fatalf("expected 1 debounced run, got %d", fired)
	}
}