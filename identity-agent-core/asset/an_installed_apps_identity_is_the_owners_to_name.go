package asset

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Which installed app may hold an app's key (ADR-072 section 4, ADR-012
// Amendment 5). A hardware attestation proves a key is held in hardware; only
// the app's identity, which the OWNER names when the app is made or enrolled,
// says it is held by THIS app's installed program and not by another program
// on the same phone. The Identity Agent compares the attestation to it; the
// app's back end never supplies it at sign-in.

// InstalledAppIdentity is what the owner says the app's installed program is.
// Each platform the app ships on names its own; a platform left out is one the
// app cannot hold a key on.
type InstalledAppIdentity struct {
	// AndroidPackage and AndroidSigners: the package name and the SHA-256 digests
	// (lower-case hex) of the signing certificates Android's key attestation
	// states for the app.
	AndroidPackage string   `json:"android_package,omitempty"`
	AndroidSigners []string `json:"android_signers,omitempty"`
	// AppleAppID is the App Attest application identifier, "<team id>.<bundle id>".
	AppleAppID string `json:"apple_app_id,omitempty"`
	// TPMKeys: the owner accepts that a TPM proves a key is in the computer's
	// TPM and NOT which program holds it, so any program of the person's on a
	// computer with a TPM could present such a key. Without it a TPM key is refused.
	TPMKeys bool `json:"tpm_keys,omitempty"`
}

// IsEmpty is whether the owner named nothing.
func (i InstalledAppIdentity) IsEmpty() bool {
	return i.AndroidPackage == "" && len(i.AndroidSigners) == 0 && i.AppleAppID == "" && !i.TPMKeys
}

// CheckInstalledAppIdentity refuses a malformed identity. Only an app that
// offers an installed front end may name one.
func CheckInstalledAppIdentity(assetType string, offered []string, id InstalledAppIdentity) error {
	if id.IsEmpty() {
		return nil
	}
	if assetType != "app" || !containsKind(offered, FrontEndInstalledApp) {
		return fmt.Errorf("installed_app_identity: only a utility app that offers an installed_app front end names one")
	}
	if (id.AndroidPackage == "") != (len(id.AndroidSigners) == 0) {
		return fmt.Errorf("installed_app_identity: an Android identity is a package name and at least one signing certificate digest")
	}
	for _, d := range id.AndroidSigners {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != 32 || d != strings.ToLower(d) {
			return fmt.Errorf("installed_app_identity: a signing certificate digest is 64 lower-case hex characters")
		}
	}
	if id.AppleAppID != "" && strings.Count(id.AppleAppID, ".") < 1 {
		return fmt.Errorf("installed_app_identity: apple_app_id is '<team id>.<bundle id>'")
	}
	return nil
}
