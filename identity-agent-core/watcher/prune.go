package watcher

import (
	"log"
	"sync"
	"time"
)

const defaultStaleTTL = 2 * 365 * 24 * time.Hour

// StartPruneLoop runs daily retention pruning (first+latest per AID, stale TTL).
//
// It returns what ends the loop and waits for a prune under way to finish, so a
// store is not closed beneath one.
func StartPruneLoop(svc *Service, interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
			}
			if err := svc.Prune(); err != nil {
				log.Printf("[watcher] prune error: %v", err)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(quit) })
		<-done
	}
}
