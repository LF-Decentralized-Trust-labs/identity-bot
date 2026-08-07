package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"identity-agent-core/server"
)

func main() {
	// Preparing the encrypted volume happens before the agent runs, and before
	// anything mounts it — so it is a command this binary answers rather than
	// a separate tool. One binary means one thing to measure.
	if len(os.Args) > 1 && os.Args[1] == "seal-volume" {
		if err := sealVolume(os.Args[2:]); err != nil {
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
