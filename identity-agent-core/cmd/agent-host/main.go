// Command agent-host makes this machine the body of an AI agent.
//
//	agent-host enrol <enrolment string> [--placement computer|vm|cloud|device]
//	agent-host status
//	agent-host call <METHOD> <path> [json body]
//
// Every command accepts --data-dir; the default is per operating system.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"identity-agent-core/agenthost"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fs.String("data-dir", agenthost.DefaultDataDir(), "where this machine's key and state are kept")
	placement := fs.String("placement", "computer", "where this machine is: computer, vm, cloud or device")
	wait := fs.Duration("wait", 15*time.Minute, "how long to wait for the owner to approve")
	_ = fs.Parse(os.Args[2:])
	h := &agenthost.Host{DataDir: *dataDir, Out: os.Stdout}

	switch cmd {
	case "enrol", "enroll":
		if fs.NArg() != 1 {
			usage()
		}
		if _, err := h.Enrol(fs.Arg(0), *placement, *wait); err != nil {
			fail(err)
		}
	case "status":
		st, err := h.Status()
		if err != nil {
			fail(err)
		}
		fmt.Printf("state: %v\nAI agent: %v\ngrade: %v\nwords: %v\ncredential: %v\n",
			st["state"], st["agent"], st["grade"], st["words"], st["credential_said"])
	case "call":
		if fs.NArg() < 2 {
			usage()
		}
		var body []byte
		if fs.NArg() > 2 {
			body = []byte(fs.Arg(2))
		}
		code, out, err := h.Call(fs.Arg(0), fs.Arg(1), body)
		if err != nil {
			fail(err)
		}
		fmt.Printf("%d\n%s\n", code, out)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  agent-host enrol <enrolment string> [--placement computer|vm|cloud|device]\n  agent-host status\n  agent-host call <METHOD> <path> [json body]")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent-host:", err)
	os.Exit(1)
}
