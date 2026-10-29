package server

import (
	"errors"
	"log"
	"time"
)

// What the Identity Agent does on every tick, until it stops: anchor its record
// where it anchors one, adopt what the device that holds the key has signed,
// ask again for withdrawals still waiting, and keep its witnesses up to date.
// Every Identity Agent runs this loop, whether or not it anchors a record.

// keepAnchoring anchors the record every anchorTick until stop closes.
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
	if _, err := s.anchorRecord(); err != nil && !errors.Is(err, errKeyElsewhere) {
		log.Printf("[record] anchoring: %v", err)
	}
	// What the device that holds the key signed and is not here yet.
	if _, err := s.adoptWhatTheDeviceSigned(nil); err != nil {
		log.Printf("[grants] %v", err)
	}
	s.askAgainForWithdrawals()
	s.witnessOwnLog()
}
