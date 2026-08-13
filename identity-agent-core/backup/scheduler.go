package backup

import (
	"encoding/base64"
	"fmt"
	"log"
	"sync"
	"time"
)

// Scheduler handles debounced event-triggered and daily backups.
type Scheduler struct {
	svc              *Service
	mu               sync.Mutex
	debounce         *time.Timer
	debounceInterval time.Duration
	lastExport       time.Time
	dailyTicker      *time.Ticker
	stopCh           chan struct{}
	mnemonicFunc     func() (string, error)
	seedFunc         func() ([]byte, error) // injected — never persisted
	afterRunHook     func(reason string)    // tests only
}

func NewScheduler(svc *Service) *Scheduler {
	return &Scheduler{
		svc:              svc,
		stopCh:           make(chan struct{}),
		debounceInterval: 5 * time.Minute,
	}
}

// SetDebounceInterval overrides the default 5-minute debounce (tests only).
func (sch *Scheduler) SetDebounceInterval(d time.Duration) {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	sch.debounceInterval = d
}

// SetSeedProvider supplies the root seed at export time.
//
// THE SEED, NOT THE WORDS. An agent holds its seed already — wrapped on its own
// disk — and can read it whenever it needs to. It does not hold the words and
// should never ask for them: a backup that waits for somebody to type a phrase
// is a backup that only happens when somebody is watching, which is the
// opposite of what a backup is for.
//
// Nothing set a provider of either kind, so every scheduled backup skipped and
// said so in a log nobody reads. That is why this exists.
func (sch *Scheduler) SetSeedProvider(fn func() ([]byte, error)) {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	sch.seedFunc = fn
}

// CanRun reports whether a backup could actually be taken right now.
//
// So a caller can say "scheduled" honestly, or say why not. Reporting success
// for something that will silently skip five minutes later is how this went
// unnoticed for as long as it did.
func (sch *Scheduler) CanRun() error {
	sch.mu.Lock()
	defer sch.mu.Unlock()
	if sch.seedFunc == nil && sch.mnemonicFunc == nil {
		return fmt.Errorf("this agent has no way to reach its own root seed, so it cannot " +
			"take a backup")
	}
	return nil
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
	interval := sch.debounceInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	sch.debounce = time.AfterFunc(interval, func() {
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
	if sch.debounce != nil {
		sch.debounce.Stop()
	}
	select {
	case <-sch.stopCh:
	default:
		close(sch.stopCh)
	}
}

// SetAfterRunHook observes debounced scheduler invocations (tests only).
func (sch *Scheduler) SetAfterRunHook(fn func(reason string)) {
	sch.afterRunHook = fn
}

func (sch *Scheduler) runBackup(reason string) {
	if sch.afterRunHook != nil {
		sch.afterRunHook(reason)
	}
	cfg, err := sch.svc.ConfigStore.LoadConfig()
	if err != nil || !cfg.Enabled {
		return
	}
	// The seed first, because an agent has one and never has the words.
	var mnemonic, seedB64 string
	if sch.seedFunc != nil {
		seed, serr := sch.seedFunc()
		if serr != nil || len(seed) == 0 {
			log.Printf("[backup] FAILED %s: this agent could not read its own root seed (%v). "+
				"No backup was taken", reason, serr)
			return
		}
		seedB64 = base64.StdEncoding.EncodeToString(seed)
	} else if sch.mnemonicFunc != nil {
		m, merr := sch.mnemonicFunc()
		if merr != nil || m == "" {
			log.Printf("[backup] FAILED %s: the words were asked for and not available (%v). "+
				"No backup was taken", reason, merr)
			return
		}
		mnemonic = m
	} else {
		log.Printf("[backup] FAILED %s: this agent has no way to reach its own root seed, so "+
			"it cannot back up at all. Nothing is being kept", reason)
		return
	}

	_, err = sch.svc.exportWithReason(mnemonic, seedB64, "", "", cfg.DefaultTiers, reason)
	if err != nil {
		log.Printf("[backup] %s export failed: %v", reason, err)
		return
	}
	sch.mu.Lock()
	sch.lastExport = time.Now()
	sch.mu.Unlock()
	log.Printf("[backup] completed %s", reason)
}
