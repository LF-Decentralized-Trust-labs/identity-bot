// Package run is how a program starts an Identity Agent: the core's own
// desktop program, and every app built on the core.
//
// Every Identity Agent starts the same way. A volume command, which a sealed
// image may run this program for, is handled first and instead of anything
// else. Otherwise the configuration is read from the environment, the server
// is made and started, and it runs until the process is told to stop. An app
// includes the add-ons it wants by importing them; what else it needs at
// start-up it gives as Options.
package run

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"identity-agent-core/server"
	"identity-agent-core/volume"
)

// Options are what an app adds to the start-up. Every field is optional.
type Options struct {
	// Name is what the start-up's log lines begin with, in brackets.
	// "identity-agent-core" when empty.
	Name string

	// BeforeConfig runs before the configuration is read from the
	// environment and before the server is made: for what must be in place
	// when they happen, such as an environment variable the configuration
	// reads or an executor a capability pack names.
	BeforeConfig func() error

	// Config adjusts the configuration read from the environment, before the
	// server is made with it.
	Config func(cfg *server.Config)

	// Prepare runs once the server is made and before it starts: for an
	// overlay's routes (MountExtraRoutes), authorizers and resolvers. What it
	// returns, when not nil, runs once the server has stopped.
	Prepare func(s *server.CoreServer, cfg server.Config) (stopped func(), err error)
}

// Main starts an Identity Agent and returns once it has stopped, after the
// process is told to stop (SIGINT or SIGTERM). Anything that keeps it from
// starting ends the process with the reason.
func Main(o Options) {
	// Asked for only once the server has started, as it always was, so a
	// signal while it starts ends the process as before.
	untilTold := func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
	}
	if err := start(o, os.Args[1:], untilTold); err != nil {
		log.Fatalf("[%s] %v", o.name(), err)
	}
}

func (o Options) name() string {
	if o.Name == "" {
		return "identity-agent-core"
	}
	return o.Name
}

// start is Main with its arguments given, and wait, which returns when the
// server is to stop.
func start(o Options, args []string, wait func()) error {
	// Volume commands run before the Identity Agent does, or instead of it.
	// One dispatcher rather than a switch here, so that a program embedding
	// this core wires up every one of them by wiring up one thing; see the
	// note in the volume package for why.
	if handled, err := volume.Handle(args); handled {
		return err
	}

	if o.BeforeConfig != nil {
		if err := o.BeforeConfig(); err != nil {
			return err
		}
	}
	cfg := server.DefaultConfig()
	if o.Config != nil {
		o.Config(&cfg)
	}

	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("Failed to initialize: %w", err)
	}
	var stopped func()
	if o.Prepare != nil {
		stopped, err = o.Prepare(srv, cfg)
		// What Prepare set up is ended whatever else happens, even when it
		// also failed: it may have opened something before it did.
		if stopped != nil {
			defer stopped()
		}
		if err != nil {
			// The server never started. Stop is asked all the same, so it
			// ends whatever it would for a server that did; for one that
			// never started it does nothing, and what New opened is released
			// as the process ends.
			srv.Stop()
			return err
		}
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("Failed to start: %w", err)
	}
	log.Printf("[%s] Server started on port %d", o.name(), srv.Port)

	wait()

	srv.Stop()
	return nil
}
