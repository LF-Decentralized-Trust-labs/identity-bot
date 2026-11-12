package asset

import (
	"fmt"
	"sort"
	"sync"

	"identity-agent-core/login"
)

// The front ends a utility app is reached by (ADR-072 §3). An app declares what
// it offers in its manifest's device_front_ends (ADR-012 Amendment 5); its
// owner may switch any of them off and cannot switch one on that it does not
// offer. The owner's Identity Agent enforces it when it issues a sign-in
// challenge, never the app's back end.

// frontEndsMu orders the read and write of one declaration.
var frontEndsMu sync.Mutex

// The two kinds of front end, as the manifest spells them.
const (
	FrontEndBrowser      = login.FrontEndBrowser
	FrontEndInstalledApp = login.FrontEndInstalledApp
)

func validFrontEnd(k string) bool { return k == FrontEndBrowser || k == FrontEndInstalledApp }

func containsKind(list []string, k string) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}

// checkKinds refuses a list with an unknown kind or a repeat.
func checkKinds(what string, kinds []string) error {
	seen := map[string]bool{}
	for _, k := range kinds {
		if !validFrontEnd(k) {
			return fmt.Errorf("%s: each must be 'installed_app' or 'browser'", what)
		}
		if seen[k] {
			return fmt.Errorf("%s: '%s' is listed twice", what, k)
		}
		seen[k] = true
	}
	return nil
}

// CheckOfferedFrontEnds checks the front ends declared for a new or enrolling
// asset. Only a utility app ("app") has any.
func CheckOfferedFrontEnds(assetType string, offered []string) error {
	if assetType != "app" {
		if len(offered) > 0 {
			return fmt.Errorf("device_front_ends: only a utility app offers front ends")
		}
		return nil
	}
	return checkKinds("device_front_ends", offered)
}

// DeclaresFrontEnds is whether a list given when an asset is made or enrols is
// the owner declaring what it offers. Only an app has any, and only a list that
// was given at all counts: nothing given (nil) is an app that has not said,
// while an empty list given is an app that offers none. A JSON reader keeps the
// two apart, which is why this is read from the list and not from its length.
func DeclaresFrontEnds(assetType string, offered []string) bool {
	return assetType == "app" && offered != nil
}

// FrontEndsAreDeclared is whether this app's front ends were declared. An app
// made before it could say has not declared, and signs people in as it always
// did; an app with a list has declared even if the flag was not written.
func (a Asset) FrontEndsAreDeclared() bool {
	return a.AssetType == "app" && (a.FrontEndsDeclared || len(a.DeviceFrontEnds) > 0)
}

// SwitchOff is the new list of switched-off front ends: every kind must be one
// the app offers. The result is in a fixed order and without repeats.
func SwitchOff(offered, off []string) ([]string, error) {
	if err := checkKinds("switched_off", off); err != nil {
		return nil, err
	}
	for _, k := range off {
		if !containsKind(offered, k) {
			return nil, fmt.Errorf("this app does not offer a '%s' front end, so there is none to switch off", k)
		}
	}
	out := append([]string(nil), off...)
	sort.Strings(out)
	return out, nil
}

// FrontEndRefusal is why a sign-in on the front end of this kind may not start,
// in words the front end can show the person; "" means it may. A utility app
// that has declared its front ends admits only a kind it offers and its owner
// has not switched off. Any other asset has no front-end setting and is not
// asked, and neither is an app made before it could declare them: for that one
// a missing list means "not declared", never "offers none".
func (a Asset) FrontEndRefusal(kind string) string {
	if !a.FrontEndsAreDeclared() {
		return ""
	}
	switch {
	case !validFrontEnd(kind):
		return "this sign-in does not say which front end it is for, 'browser' or 'installed_app'"
	case !containsKind(a.DeviceFrontEnds, kind):
		return fmt.Sprintf("this utility app does not offer a %s front end", kindWords(kind))
	case containsKind(a.FrontEndsOff, kind):
		return fmt.Sprintf("the owner of this utility app has switched off its %s front end", kindWords(kind))
	}
	return ""
}

func kindWords(k string) string {
	if k == FrontEndInstalledApp {
		return "installed-app"
	}
	return "browser"
}

// FrontEnds is what the owner reads and sets: for each front end the app
// offers, whether it is on.
type FrontEnds struct {
	// Declared is false for an app made before it could say what it offers;
	// its Offered is then empty and means "not said", not "none".
	Declared    bool     `json:"declared"`
	Offered     []string `json:"offered"`
	SwitchedOff []string `json:"switched_off"`
}

// ErrFrontEndsAlreadyDeclared is the refusal of a second declaration.
var ErrFrontEndsAlreadyDeclared = fmt.Errorf("this app has already declared its front ends, and what it offers is not changed after that")

func frontEndsOf(a Asset) FrontEnds {
	f := FrontEnds{Declared: a.FrontEndsAreDeclared(), Offered: a.DeviceFrontEnds, SwitchedOff: a.FrontEndsOff}
	if f.Offered == nil {
		f.Offered = []string{}
	}
	if f.SwitchedOff == nil {
		f.SwitchedOff = []string{}
	}
	return f
}
