package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"identity-agent-core/server"
	"identity-agent-core/volume"
)

func main() {
	// Volume commands run before the Identity Agent does, or instead of it. One
	// dispatcher rather than a switch here, so that an overlay embedding this
	// core wires up every one of them by wiring up one thing — see the note in
	// the volume package for why.
	if handled, err := volume.Handle(os.Args[1:]); handled {
		if err != nil {
			log.Fatalf("[identity-agent-core] %v", err)
		}
		return
	}

	cfg := server.DefaultConfig()

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("[identity-agent-core] Failed to initialize: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("[identity-agent-core] Failed to start: %v", err)
	}

	log.Printf("[identity-agent-core] Server started on port %d", srv.Port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	srv.Stop()
}
