package watcher

import (
	"log"
	"time"
)

const defaultStaleTTL = 2 * 365 * 24 * time.Hour

// StartPruneLoop runs daily retention pruning (first+latest per AID, stale TTL).
func StartPruneLoop(svc *Service, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := svc.Prune(); err != nil {
				log.Printf("[watcher] prune error: %v", err)
			}
		}
	}()
}
