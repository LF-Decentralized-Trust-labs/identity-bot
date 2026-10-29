package main

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
)

// The setup printed for a brain run as its own user allows sudo to start
// only agent-host brain-env around a brain, never the brain itself, never
// with the right to pass variables on (SETENV), and keeps sudo's input and
// output logging off for agent-host, whose input holds the sign-in.
func TestTheBrainUserSetupKeepsTheSignInOutOfSudo(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the setup is printed for macOS and Linux")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	brainUserSetup("agentbrain")
	os.Stdout = stdout
	_ = w.Close()
	b, _ := io.ReadAll(r)
	out := string(b)
	for _, want := range []string{
		"'Defaults!/usr/local/bin/agent-host !log_input, !log_output'",
		"NOPASSWD: /usr/local/bin/agent-host brain-env -- $b *, " +
			"/usr/local/bin/agent-host brain-env -- /usr/local/bin/agent-host brain-home -- $b *",
		"sudo visudo -cf /tmp/agent-host.sudoers",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the setup does not say %q", want)
		}
	}
	for _, never := range []string{"SETENV", "preserve-env"} {
		if strings.Contains(out, never) {
			t.Errorf("the setup still allows %s", never)
		}
	}
}
