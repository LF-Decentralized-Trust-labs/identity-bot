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

// A lock suspends the scheduler: its timers end, a pending backup does not
// fire, and the daily timer can start again on unlock. Stop stays final.
func TestSchedulerSuspendEndsTimersAndStartDailyBeginsThemAgain(t *testing.T) {
	svc := NewService(t.TempDir(), nil)
	svc.Scheduler.SetDebounceInterval(30 * time.Millisecond)
	cfg := DefaultConfig()
	cfg.Enabled = true
	if err := svc.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	var fired int32
	svc.Scheduler.SetAfterRunHook(func(string) { atomic.AddInt32(&fired, 1) })

	svc.Scheduler.StartDaily()
	svc.Scheduler.TriggerEvent(string(EventProfileChange))
	svc.Scheduler.Suspend()
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&fired); n != 0 {
		t.Fatalf("a backup fired after the scheduler was suspended: %d", n)
	}
	done := make(chan struct{})
	go func() { svc.Scheduler.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the daily loop was still running after Suspend")
	}

	svc.Scheduler.StartDaily() // on unlock
	svc.Scheduler.TriggerEvent(string(EventProfileChange))
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&fired); n != 1 {
		t.Fatalf("the scheduler did not work again after StartDaily: %d", n)
	}
	svc.Scheduler.Stop()
	svc.Scheduler.StartDaily()
	svc.Scheduler.Wait()
}
