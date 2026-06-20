package backup

import (
	"log"
	"sync"
	"time"
)

// Scheduler handles debounced event-triggered and daily backups.
type Scheduler struct {
	svc          *Service
	mu           sync.Mutex
	debounce     *time.Timer
	lastExport   time.Time
	dailyTicker  *time.Ticker
	stopCh       chan struct{}
	mnemonicFunc func() (string, error) // injected — never persisted
}

func NewScheduler(svc *Service) *Scheduler {
	return &Scheduler{
		svc:    svc,
		stopCh: make(chan struct{}),
	}
}

// SetMnemonicProvider supplies the seed at export time (transient, never stored).
func (sch *Scheduler) SetMnemonicProvider(fn func() (string, error)) {
	sch.mnemonicFunc = fn
}

// TriggerEvent schedules a debounced backup (5 min after last event).
func (sch *Scheduler) TriggerEvent(reason string) {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	if sch.debounce != nil {
		sch.debounce.Stop()
	}
	sch.debounce = time.AfterFunc(5*time.Minute, func() {
		sch.runBackup(reason)
	})
}

// StartDaily begins the daily minimum timer.
func (sch *Scheduler) StartDaily() {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	if sch.dailyTicker != nil {
		return
	}
	sch.dailyTicker = time.NewTicker(24 * time.Hour)
	go func() {
		for {
			select {
			case <-sch.dailyTicker.C:
				sch.runBackup("daily_timer")
			case <-sch.stopCh:
				return
			}
		}
	}()
}

func (sch *Scheduler) Stop() {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	if sch.dailyTicker != nil {
		sch.dailyTicker.Stop()
	}
	close(sch.stopCh)
}

func (sch *Scheduler) runBackup(reason string) {
	cfg, err := sch.svc.ConfigStore.LoadConfig()
	if err != nil || !cfg.Enabled {
		return
	}
	if sch.mnemonicFunc == nil {
		log.Printf("[backup] skip %s: no mnemonic provider", reason)
		return
	}
	mnemonic, err := sch.mnemonicFunc()
	if err != nil || mnemonic == "" {
		log.Printf("[backup] skip %s: mnemonic unavailable", reason)
		return
	}
	_, err = sch.svc.Export(mnemonic, "", "", cfg.DefaultTiers)
	if err != nil {
		log.Printf("[backup] %s export failed: %v", reason, err)
		return
	}
	sch.mu.Lock()
	sch.lastExport = time.Now()
	sch.mu.Unlock()
	log.Printf("[backup] completed %s", reason)
}