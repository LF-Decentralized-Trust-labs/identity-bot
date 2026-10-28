package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"identity-agent-core/agenthost"
	"identity-agent-core/agentmachine"
)

// A provider whose program says the name is already taken leaves that machine
// alone: it never asks the program to remove it, and the request fails saying
// why. Every call names the request and the provider, so the program can refuse
// to touch a machine made for anything else.
func TestAMachineWhoseNameIsTakenIsNeverDestroyed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	w, _, providerHost := machineWorld(t)
	dir := t.TempDir()
	program := filepath.Join(dir, "make-machines")
	script := "#!/bin/sh\necho \"$1 $2 request=$AGENT_MACHINE_REQUEST provider=$AGENT_MACHINE_PROVIDER\" >> " + dir + "/calls\n" +
		"if [ \"$1\" = make ]; then echo \"$2 already exists\" >&2; exit 3; fi\n"
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = providerHost.Provide(ctx, agenthost.ProvideOptions{Program: program, Offers: []string{"screen"}})
	}()
	t.Cleanup(func() { cancel(); <-done })

	agent := w.provision(t, "Designer", []string{capabilityMessageAgent})
	base := "/api/mcp/agents/" + agent.ID
	var provider string
	waitFor(t, "the provider to offer", func() bool {
		ps, _ := w.s.machines().Providers()
		if len(ps) == 1 {
			provider = ps[0].Body
		}
		return provider != ""
	})
	st, err := providerHost.Status()
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := st["binding_id"].(string)
	if code, _, raw := w.asOwner(t, "POST", base+"/machine-requests", `{"provider":"`+provider+`"}`); code != http.StatusCreated {
		t.Fatalf("asking for a machine: %d %s", code, raw)
	}
	var j agentmachine.Job
	waitFor(t, "the request to fail", func() bool {
		j = w.machineRequest(t, agent.ID)
		return j.State == agentmachine.StateFailed
	})
	if !strings.Contains(j.Detail, "already exists") || !strings.Contains(j.Detail, "left alone") {
		t.Fatalf("the request failed saying %q", j.Detail)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if strings.Contains(string(calls), "remove") {
		t.Fatalf("the program was asked to remove a machine that was not this request's:\n%s", calls)
	}
	want := "make " + j.MachineName + " request=" + j.ID + " provider=" + binding
	if !strings.Contains(string(calls), want) {
		t.Fatalf("the program was not told which request and provider: got\n%s\nwant %q", calls, want)
	}
}
