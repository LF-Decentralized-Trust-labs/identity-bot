package hostlink_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Code in another module cannot reach the server's add-on handle. It cannot
// name hostlink.Token, so no value it writes converts to one; and the token
// it can still conjure without naming it — a zero value, inferred from the
// function's own parameter by a generic call or made by reflect — is refused
// when it is used. This builds and runs a module of its own that depends on
// this one, as an app built on the core would.
func TestAnotherModuleCannotMakeAToken(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module of its own")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	core, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(core, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	// outsider runs go with args in a module of its own whose main.go is src.
	outsider := func(t *testing.T, src string, args ...string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		mod := "module outsider\n\ngo 1.25.0\n\nrequire identity-agent-core v0.0.0\n\nreplace identity-agent-core => " + core + "\n"
		for _, sub := range []string{"relayproto", "witnessproto"} {
			mod += "replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/" + sub + " => " + filepath.Join(core, sub) + "\n"
		}
		for name, body := range map[string]string{"go.mod": mod, "go.sum": string(sum), "main.go": src} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(goBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	program := func(body string) string {
		return "package main\n\nimport \"identity-agent-core/server\"\n\nfunc main() {\n" + body + "\n}\n"
	}
	build := func(t *testing.T, body string) (string, error) {
		return outsider(t, program(body), "build", "-o", os.DevNull, ".")
	}

	// The control: an outside module that uses the core's public API builds,
	// so a failure below is the token's doing and not the setup's.
	if out, err := build(t, "_ = server.DefaultConfig()"); err != nil {
		t.Fatalf("an outside module could not build against the core at all: %v\n%s", err, out)
	}

	// Writing a token: does not compile.
	for _, conjured := range []string{"struct{}{}", "struct{ _ byte }{}"} {
		for _, call := range []string{
			"_ = server.AddonHost(nil, " + conjured + ")",
			"_ = server.AddonFixtures(" + conjured + ")",
		} {
			out, err := build(t, call)
			if err == nil {
				t.Errorf("an outside module reached the add-on handle with %s", call)
				continue
			}
			if !strings.Contains(out, "cannot use") {
				t.Errorf("%s failed for another reason than the token: %s", call, out)
			}
		}
	}

	// Conjuring one without naming it: compiles, and is refused when used.
	for name, src := range map[string]string{
		"a generic call": `package main

import (
	"fmt"

	"identity-agent-core/server"
)

func call[T any](f func(*server.CoreServer, T) any, s *server.CoreServer) any {
	var zero T
	return f(s, zero)
}

func fixtures[T any](f func(T) any) any {
	var zero T
	return f(zero)
}

func main() {
	if h := call(server.AddonHost, nil); h != nil {
		fmt.Println("REACHED the handle")
	}
	if f := fixtures(server.AddonFixtures); f != nil {
		fmt.Println("REACHED the fixtures")
	}
}
`,
		"reflect": `package main

import (
	"fmt"
	"reflect"

	"identity-agent-core/server"
)

func main() {
	fn := reflect.ValueOf(server.AddonHost)
	var s *server.CoreServer
	out := fn.Call([]reflect.Value{reflect.ValueOf(s), reflect.Zero(fn.Type().In(1))})
	if !out[0].IsNil() {
		fmt.Println("REACHED the handle")
	}
	fx := reflect.ValueOf(server.AddonFixtures)
	if out := fx.Call([]reflect.Value{reflect.Zero(fx.Type().In(0))}); !out[0].IsNil() {
		fmt.Println("REACHED the fixtures")
	}
}
`,
	} {
		out, err := outsider(t, src, "run", ".")
		if strings.Contains(out, "REACHED") || err == nil {
			t.Errorf("an outside module reached the add-on handle with %s:\n%s", name, out)
			continue
		}
		if !strings.Contains(out, "not this module's") {
			t.Errorf("%s failed for another reason than the token being refused:\n%s", name, out)
		}
	}
}
