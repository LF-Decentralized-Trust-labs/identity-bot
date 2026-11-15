package login

import (
	"fmt"
	"strings"
	"unicode"
)

// The kinds of front end a sign-in to a utility app can name (ADR-072 section 3).
const (
	FrontEndBrowser      = "browser"
	FrontEndInstalledApp = "installed_app"
)

// CheckFrontEnd refuses a front-end kind that is not one of the two, and
// accepts "" (a challenge that names none). The person's agent runs it on the
// signed challenge before showing consent, and a verifier runs it on the kind
// it expects.
func CheckFrontEnd(kind string) error {
	switch kind {
	case "", FrontEndBrowser, FrontEndInstalledApp:
		return nil
	}
	return fmt.Errorf("a sign-in names a front end that is not 'browser' or 'installed_app'")
}

// The platforms an installed app's key can be proved on (the core's hardware
// verifiers: Android key attestation, Apple App Attest, a TPM).
const (
	DeviceAndroid = "android"
	DeviceApple   = "apple"
	DeviceTPM     = "tpm"
)

// MaxDeviceNameRunes bounds the label an installed app gives its device, so it
// fits a row of the consent screen and cannot push the rest off it.
const MaxDeviceNameRunes = 48

// CleanDeviceName makes what an installed app calls its device fit to show:
// control, line-break, and direction-changing characters are dropped (a name
// that reorders the text around it could make a row read as something else),
// runs of spaces become one, and it is cut to MaxDeviceNameRunes. "" if
// nothing is left.
func CleanDeviceName(s string) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r), r == unicode.ReplacementChar:
			continue
		}
		if space {
			if n+2 > MaxDeviceNameRunes {
				break
			}
			b.WriteRune(' ')
			n++
			space = false
		}
		if n+1 > MaxDeviceNameRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// CheckDevice refuses a signed challenge that names a device it should not:
// only an installed app's sign-in has one, the platform is one of the three the
// core proves, a name comes only with a platform, and the name is already as
// CleanDeviceName leaves it. The person's Identity Agent runs it before it
// shows consent, so what the screen says about the device is bounded whoever
// signed the challenge.
func CheckDevice(frontEnd, platform, name string) error {
	if platform == "" && name == "" {
		return nil
	}
	if frontEnd != FrontEndInstalledApp {
		return fmt.Errorf("a sign-in names a device only for an installed app")
	}
	switch platform {
	case DeviceAndroid, DeviceApple, DeviceTPM:
	default:
		return fmt.Errorf("a sign-in names a device that is not 'android', 'apple' or 'tpm'")
	}
	if name != CleanDeviceName(name) {
		return fmt.Errorf("a sign-in names a device with a name that is not fit to show")
	}
	return nil
}
