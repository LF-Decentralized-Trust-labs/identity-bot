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
// else. An add-on is a package an app may include, from a module of its own;
// it includes one by importing it, which registers it with the server
// (server.RegisterAddon). An add-on reaches the core through the plug-in
// point, package addon, and its tests through addon/addontest. So neither the
// phone core (mobilecore) nor the core's desktop program (the module's main
// package) may come to depend on the plug-in point, or on a package of this
// module that does, on any platform the phone core is built for.
//
// What only add-ons use is found, not listed: the plug-in point's packages,
// and every package of this module that depends on one of them.

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

// pluginPoint are the packages of the plug-in point.
const pluginPoint = module + "/addon"

// addOnOnly are the packages of this module only add-ons use, on one
// platform: the plug-in point's, and every package that depends on one.
func addOnOnly(t *testing.T, goos, goarch string) map[string]bool {
	t.Helper()
	only := map[string]bool{}
	for _, line := range goList(t, goos, goarch, "-f", "{{.ImportPath}}|{{join .Deps \",\"}}", "./...") {
		path, deps, _ := strings.Cut(line, "|")
		if path == pluginPoint || strings.HasPrefix(path, pluginPoint+"/") {
			only[path] = true
			continue
		}
		for _, d := range strings.Split(deps, ",") {
			if d == pluginPoint || strings.HasPrefix(d, pluginPoint+"/") {
				only[path] = true
				break
			}
		}
	}
	return only
}

func TestNoCoreProgramLinksAnAddOn(t *testing.T) {
	for _, p := range platforms {
		name := p.goos
		if name == "" {
			name = runtime.GOOS
		}
		only := addOnOnly(t, p.goos, p.goarch)
		if !only[pluginPoint] || !only[pluginPoint+"/addontest"] {
			t.Fatalf("the plug-in point's packages are not found on %s (found %v); the search no longer finds them", name, only)
		}
		for _, prog := range corePrograms {
			var linked []string
			for _, d := range goList(t, p.goos, p.goarch, "-deps", prog) {
				if only[d] {
					linked = append(linked, d)
				}
			}
			sort.Strings(linked)
			if len(linked) > 0 {
				t.Errorf("%s links what only add-ons use, on %s: %s; an add-on is included by an app that imports it, never by the core",
					prog, name, strings.Join(linked, ", "))
			}
		}
	}
}
