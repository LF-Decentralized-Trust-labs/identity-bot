package mobilecore

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The core's own programs link no add-on.
//
// Every app built on this core carries whatever the phone core links, on
// every phone, and the core's own desktop program is the core and nothing
// else. An add-on is a package an app may include; it includes one by
// importing it, which registers it with the server (server.RegisterAddon).
// So neither the phone core (mobilecore) nor the core's desktop program (the
// module's main package) may come to depend on an add-on, or on a package
// only add-ons use, on any platform the phone core is built for.
//
// The add-ons are found, not listed: every package of this module that
// calls server.RegisterAddon outside its tests. What only they use is
// whatever they depend on that the server does not.

// module is this module's path, as package paths begin.
const module = "identity-agent-core"

// corePrograms are the packages that must link no add-on, by path.
var corePrograms = []string{module + "/mobilecore", module}

// platforms are where the phone core and the desktop program are built.
var platforms = []struct{ goos, goarch string }{
	{"", ""}, // this machine
	{"ios", "arm64"},
	{"android", "arm64"},
}

func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

// goList runs go list in the module's root for one platform.
func goList(t *testing.T, goos, goarch string, args ...string) []string {
	t.Helper()
	cmd := exec.Command(goTool(), append([]string{"list"}, args...)...)
	cmd.Dir = ".."
	cmd.Env = os.Environ()
	if goos != "" {
		// The phone builds use cgo, and iOS cannot be built without it.
		cmd.Env = append(cmd.Env, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=1")
	}
	out, err := cmd.Output()
	if err != nil {
		msg := ""
		if ee, ok := err.(*exec.ExitError); ok {
			msg = string(ee.Stderr)
		}
		t.Fatalf("go list %s (GOOS=%s): %v\n%s", strings.Join(args, " "), goos, err, msg)
	}
	return strings.Fields(string(out))
}

// addOnPackages are this module's packages that register an add-on.
func addOnPackages(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, line := range goList(t, "", "", "-f", "{{.ImportPath}}|{{.Dir}}|{{join .GoFiles \",\"}}", "./...") {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		for _, f := range strings.Split(parts[2], ",") {
			src, err := os.ReadFile(filepath.Join(parts[1], f))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(src), "server.RegisterAddon(") {
				found = append(found, parts[0])
				break
			}
		}
	}
	sort.Strings(found)
	return found
}

func TestNoCoreProgramLinksAnAddOn(t *testing.T) {
	addOns := addOnPackages(t)
	if len(addOns) < 2 {
		t.Fatalf("found only %v registering an add-on; the search no longer finds them", addOns)
	}
	for _, p := range platforms {
		name := p.goos
		if name == "" {
			name = runtime.GOOS
		}
		server := map[string]bool{}
		for _, d := range goList(t, p.goos, p.goarch, "-deps", module+"/server") {
			server[d] = true
		}
		// What only add-ons bring: the add-ons and every package they need
		// that the server does not.
		addOnOnly := map[string]string{}
		for _, a := range addOns {
			for _, d := range goList(t, p.goos, p.goarch, "-deps", a) {
				if strings.HasPrefix(d, module+"/") && !server[d] {
					if _, seen := addOnOnly[d]; !seen {
						addOnOnly[d] = a
					}
				}
			}
		}
		for _, prog := range corePrograms {
			var linked []string
			for _, d := range goList(t, p.goos, p.goarch, "-deps", prog) {
				if a, ok := addOnOnly[d]; ok {
					linked = append(linked, d+" (from "+a+")")
				}
			}
			sort.Strings(linked)
			if len(linked) > 0 {
				t.Errorf("%s links what only add-ons bring, on %s: %s; an add-on is included by an app that imports it, never by the core",
					prog, name, strings.Join(linked, ", "))
			}
		}
	}
}
