package mobilecore

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The phone core links no add-on.
//
// Every app built on this core carries whatever mobilecore links, on every
// phone. An add-on is a part not every Identity Agent needs; an app includes
// one by importing its package, which registers it with the server
// (server.RegisterAddon), and the phone core must never come to depend on one.
//
// Some add-ons are still linked, because their code still sits in the server
// package. Each is listed in stillLinked with the reason. The list only shrinks: the test fails if mobilecore depends on an
// add-on that is not on it, and fails again once one on it is no longer
// linked, so that it is taken off.

// addOns are the packages that are add-ons, by their path in this module.
var addOns = []string{
	// AI agents.
	"agentbody", "agentmachine", "agentmessage", "agenthost", "brainsignin",
	"conversation", "conversationbundle", "githubapp", "lending", "screenview",
	// Sandboxed apps.
	"sandbox", "appcall", "endpointclient",
}

// stillLinked are the add-ons mobilecore depends on today, and why.
var stillLinked = map[string]string{
	"agentbody":          aiAgentsInServer,
	"agentmachine":       aiAgentsInServer,
	"agentmessage":       aiAgentsInServer,
	"brainsignin":        aiAgentsInServer,
	"conversation":       aiAgentsInServer,
	"conversationbundle": aiAgentsInServer,
	"githubapp":          aiAgentsInServer,
	"lending":            aiAgentsInServer,
	"screenview":         aiAgentsInServer,
	"sandbox":            "the server still makes the sandbox manager, which the AI-agent code calls capabilities through",
	"appcall":            "the sandbox package imports it",
}

// aiAgentsInServer is why the AI-agent packages are still linked.
const aiAgentsInServer = "the AI-agent add-on still registers from inside the server package " +
	"(ai_agents_add_on.go): the core asks it only through the add-on seam, but its code " +
	"still uses core internals that are not exported"

func TestThePhoneCoreLinksNoAddOn(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("could not list what mobilecore depends on: %v", err)
	}
	const module = "identity-agent-core/"
	linked := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		if strings.HasPrefix(p, module) {
			linked[strings.TrimPrefix(p, module)] = true
		}
	}
	var newly, gone []string
	for _, a := range addOns {
		_, known := stillLinked[a]
		switch {
		case linked[a] && !known:
			newly = append(newly, a)
		case !linked[a] && known:
			gone = append(gone, a)
		}
	}
	for a := range stillLinked {
		if !contains(addOns, a) {
			t.Errorf("%s is listed as still linked but is not an add-on", a)
		}
	}
	sort.Strings(newly)
	sort.Strings(gone)
	if len(newly) > 0 {
		t.Errorf("the phone core now depends on the add-on(s) %s; an add-on is included by importing it, never by the core", strings.Join(newly, ", "))
	}
	if len(gone) > 0 {
		t.Errorf("the phone core no longer depends on %s; take it off stillLinked so it cannot come back unnoticed", strings.Join(gone, ", "))
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
