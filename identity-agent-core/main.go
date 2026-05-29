package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"identity-agent-core/server"
)

func main() {
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
