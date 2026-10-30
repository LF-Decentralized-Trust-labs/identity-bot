package server

import (
	"log"
	"os"
	"time"
)

// What the Identity Agent does on every tick, until it stops: what each
// add-on does on a tick (anchoring the record, where one is anchored), then
// adopt what the device that holds the key has signed, ask again for
// withdrawals still waiting, and keep its witnesses up to date. Every Identity
// Agent runs this loop, whatever add-ons it includes.

// keepAnchoring runs a tick every anchorTick until stop closes.
func (s *CoreServer) keepAnchoring(stop <-chan struct{}) {
	t := time.NewTicker(anchorTick())
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.tick()
		}
	}
}

// tick is what runs every anchorTick.
func (s *CoreServer) tick() {
	s.addonsTick()
	// What the device that holds the key signed and is not here yet.
	if _, err := s.adoptWhatTheDeviceSigned(nil); err != nil {
		log.Printf("[grants] %v", err)
	}
	s.askAgainForWithdrawals()
	s.witnessOwnLog()
}

var (
	// anchorInterval is how far apart two ticks are, unless an add-on needs
	// them closer.
	anchorInterval = durationFromEnv("RECORD_ANCHOR_INTERVAL", 5*time.Minute)
)

func durationFromEnv(name string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(name)); err == nil && d > 0 {
		return d
	}
	return def
}

// anchorTick is how often the loop ticks: the interval, or sooner where an
// add-on needs it (the record's anchoring ticks within half the time a quiet
// conversation takes to close, so a conversation's last entry is anchored
// before it closes).
func anchorTick() time.Duration {
	if at := addonsTickAtMost(); at > 0 && at < anchorInterval {
		return at
	}
	return anchorInterval
}
