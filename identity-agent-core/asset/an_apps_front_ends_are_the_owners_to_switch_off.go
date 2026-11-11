package asset

import (
	"fmt"
	"sort"
)

// The front ends a utility app is reached by (ADR-072 §3). An app declares what
// it offers in its manifest's device_front_ends (ADR-012 Amendment 5); its
// owner may switch any of them off and cannot switch one on that it does not
// offer. The owner's Identity Agent enforces it when it issues a sign-in
// challenge, never the app's back end.

// The two kinds of front end, as the manifest spells them.
const (
	FrontEndBrowser      = "browser"
	FrontEndInstalledApp = "installed_app"
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
// admits only a kind it offers and its owner has not switched off. Any other
// asset has no front-end setting and is not asked.
func (a Asset) FrontEndRefusal(kind string) string {
	if a.AssetType != "app" {
		return ""
	}
	switch {
	case !validFrontEnd(kind):
		return "this sign-in does not say which front end it is for, 'browser' or 'installed_app'"
	case !containsKind(a.DeviceFrontEnds, kind):
		return fmt.Sprintf("this app does not offer a %s front end", kindWords(kind))
	case containsKind(a.FrontEndsOff, kind):
		return fmt.Sprintf("the owner of this app has switched off its %s front end", kindWords(kind))
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
	Offered     []string `json:"offered"`
	SwitchedOff []string `json:"switched_off"`
}

func frontEndsOf(a Asset) FrontEnds {
	f := FrontEnds{Offered: a.DeviceFrontEnds, SwitchedOff: a.FrontEndsOff}
	if f.Offered == nil {
		f.Offered = []string{}
	}
	if f.SwitchedOff == nil {
		f.SwitchedOff = []string{}
	}
	return f
}
