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
	// TPMKeys: the owner accepts a key in a physical TPM chip (a discrete chip, a
	// firmware TPM in the CPU, or Pluton), which proves the key is in the
	// computer's chip and NOT which program holds it, so any program of the
	// person's on a computer with such a TPM could present it. A virtual or
	// cloud TPM, whose key the hypervisor's operator can read, is accepted only when VirtualTPMKeys is also set.
	// Without it a TPM key is refused.
	TPMKeys bool `json:"tpm_keys,omitempty"`
	// VirtualTPMKeys: on top of TPMKeys, the owner also accepts a key in a virtual or cloud
	// TPM (a virtual machine's, in Hyper-V or Azure). Such a key is held by the hypervisor, so
	// whoever operates the hypervisor can read it and sign as the person; a physical chip
	// gives no one that power. It is a declaration of its own, never implied by TPMKeys, and
	// it is only meaningful with it (CheckInstalledAppIdentity).
	VirtualTPMKeys bool `json:"virtual_tpm_keys,omitempty"`
}

// VirtualTPMKeysWarning is the owner-facing sentence for the virtual_tpm_keys declaration, for
// every screen that offers it, so the owner is told the same true thing wherever they are asked.
const VirtualTPMKeysWarning = "A virtual or cloud computer's security chip is run by whoever runs that computer's host, and they can read its keys and sign in as the person. Allow it only if you trust them."

// AcceptsVirtualTPM is whether a virtual or cloud TPM's key is accepted: only where the owner
// accepts TPM keys at all and has also said they accept a virtual one.
func (i InstalledAppIdentity) AcceptsVirtualTPM() bool { return i.TPMKeys && i.VirtualTPMKeys }

// IsEmpty is whether the owner named nothing.
func (i InstalledAppIdentity) IsEmpty() bool {
	return i.AndroidPackage == "" && len(i.AndroidSigners) == 0 && i.AppleAppID == "" && !i.TPMKeys && !i.VirtualTPMKeys
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
	if id.VirtualTPMKeys && !id.TPMKeys {
		return fmt.Errorf("installed_app_identity: virtual_tpm_keys is on top of tpm_keys: a virtual TPM is accepted only where a physical one is")
	}
	if id.AppleAppID != "" && strings.Count(id.AppleAppID, ".") < 1 {
		return fmt.Errorf("installed_app_identity: apple_app_id is '<team id>.<bundle id>'")
	}
	return nil
}
