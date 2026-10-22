package childenv

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// A child started with this environment cannot see the local owner secret,
// even while the parent still holds it.
func TestAChildNeverSeesTheLocalOwnerSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /usr/bin/env")
	}
	t.Setenv(LocalOwnerSecretEnv, "the-secret-a-child-must-not-see-0123456789")
	t.Setenv("CHILDENV_KEPT", "yes")
	cmd := exec.Command("env")
	cmd.Env = Environ()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), LocalOwnerSecretEnv) {
		t.Fatalf("the child saw the secret:\n%s", out)
	}
	if !strings.Contains(string(out), "CHILDENV_KEPT=yes") {
		t.Fatal("the rest of the environment was not passed on")
	}
	_ = os.Getenv
}
