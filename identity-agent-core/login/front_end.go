package login

import (
	"fmt"
	"unicode"

	"identity-agent-core/backendaddr"
	"identity-agent-core/buildmode"
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
// verifiers: Android key attestation, Apple App Attest, a TPM). A TPM the core
// proved is a virtual or cloud computer's (its owner opted in to those) signs
// as DeviceVirtualTPM, so the person is told that whoever runs its host can read
// the key.
const (
	DeviceAndroid    = "android"
	DeviceApple      = "apple"
	DeviceTPM        = "tpm"
	DeviceVirtualTPM = "virtual_tpm"
)

// MaxDeviceNameRunes bounds the label an installed app gives its device, so it
// fits a row of the consent screen and cannot push the rest off it.
const MaxDeviceNameRunes = 48

// maxMarksPerLetter bounds the combining marks kept after one character, so a
// name cannot stack marks that draw over the rows around it. Two is enough for
// the scripts that use more than one (Vietnamese, Devanagari).
const maxMarksPerLetter = 2

// blankLetters are characters Unicode counts as letters or symbols that draw
// nothing, so a name of them would look empty or hide a gap.
var blankLetters = map[rune]bool{
	0x115F: true, 0x1160: true, 0x3164: true, 0xFFA0: true, // Hangul fillers
	0x2800: true, // braille pattern blank
}

// CleanDeviceName makes what an installed app calls its device fit to show.
// It keeps only letters, digits, punctuation, symbols and spaces, so control,
// line-break, direction-changing, private-use, unassigned and invisible
// characters are dropped (a name that reorders the text around it could make a
// row read as something else). It keeps at most maxMarksPerLetter combining
// marks after a character, and a zero-width joiner or non-joiner only between
// two visible characters (emoji sequences and Persian or Indic names need them).
// Runs of spaces become one, and it is cut to MaxDeviceNameRunes. "" if nothing
// is left. Lookalike letters from other scripts are not changed: the name is
// shown as the installed app's word, never as a fact.
func CleanDeviceName(s string) string {
	var out []rune
	space, joiner := false, rune(0)
	marks := 0
	put := func(r rune) bool {
		if len(out)+1 > MaxDeviceNameRunes {
			return false
		}
		out = append(out, r)
		return true
	}
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || unicode.Is(unicode.Zs, r):
			space, joiner = len(out) > 0, 0
			continue
		case r == 0x200C || r == 0x200D:
			if len(out) > 0 && !space {
				joiner = r
			}
			continue
		case blankLetters[r]:
			continue
		case unicode.Is(unicode.M, r):
			// A mark belongs to the character before it: none at the start or
			// after a space, and only a few on one character.
			if len(out) == 0 || space || joiner != 0 || marks >= maxMarksPerLetter {
				continue
			}
			if !put(r) {
				return string(out)
			}
			marks++
			continue
		case !unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S):
			continue
		}
		if space {
			if len(out)+2 > MaxDeviceNameRunes {
				break
			}
			out = append(out, ' ')
			space = false
		}
		if joiner != 0 {
			if len(out)+2 > MaxDeviceNameRunes {
				break
			}
			out = append(out, joiner)
			joiner = 0
		}
		if !put(r) {
			break
		}
		marks = 0
	}
	return string(out)
}

// CheckDevice refuses a signed challenge that names a device it should not:
// only an installed app's sign-in has one, the platform is one of those the
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
	case DeviceAndroid, DeviceApple, DeviceTPM, DeviceVirtualTPM:
	default:
		return fmt.Errorf("a sign-in names a device that is not 'android', 'apple', 'tpm' or 'virtual_tpm'")
	}
	if name != CleanDeviceName(name) {
		return fmt.Errorf("a sign-in names a device with a name that is not fit to show")
	}
	return nil
}

// inDev says whether this is a development build, which may name a back end on
// this machine. A variable so a test can say it is.
var inDev = buildmode.IsDev

// CheckUtilityAppAddress checks the relay identifier and the back-end address a
// signed challenge names for a utility app, before the person is asked and before
// either is kept (a person's Identity Agent keeps both with a browser sign-in, to
// know where to send the end of a session). A challenge that names neither passes:
// those are for something that is not a utility app. What it names must be one
// the shared rule accepts (package backendaddr), so a site cannot have the end of
// a session sent to an address inside the person's own network or to this machine.
func CheckUtilityAppAddress(c *ChallengeBundle) error {
	if c.RelayID != "" {
		if err := backendaddr.CheckRelayID(c.RelayID); err != nil {
			return fmt.Errorf("a sign-in names a relay identifier this agent will not keep: %w", err)
		}
	}
	if c.BackEnd != "" {
		if err := backendaddr.Check(c.BackEnd, inDev()); err != nil {
			return fmt.Errorf("a sign-in names a back-end address this agent will not keep: %w", err)
		}
	}
	return nil
}
