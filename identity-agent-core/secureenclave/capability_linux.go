//go:build linux && !android

package secureenclave

// What a Linux machine can protect a key with.
//
// The question is narrower than it first looks, and getting the framing wrong
// is easy: this asks what can protect THIS PROCESS'S key, not what the machine
// is capable of in general. An SEV-SNP host can launch sealed guests and cannot
// protect its own keys with any of that machinery — the sealing applies to the
// guests, not to the software that started them. So /dev/sev is a provider
// capability and never a key-protection one, while /dev/sev-guest means we are
// running inside the sealed thing and it counts.
//
// Everything else here is one idea applied repeatedly: ask "is it there" and
// "can I use it" as separate questions, because a single open() collapses them
// and EACCES becomes indistinguishable from ENOENT. That is the whole defect
// this package is being fixed for, and on Linux it is not an edge case — the
// standard udev rule ships /dev/tpmrm0 as 0660 root:tss, so any process not in
// the tss group meets it on a machine whose TPM is perfect.
//
// Measured on real hardware 2026-07-29: /dev/sev is 0600 root:root, and an
// unprivileged stat succeeds while open is denied. That is the split, and it is
// no longer a claim.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	tpmResourceMgr = "/dev/tpmrm0"
	tpmRaw         = "/dev/tpm0"
	tpmClassDir    = "/sys/class/tpm"
	acpiTPM2Table  = "/sys/firmware/acpi/tables/TPM2"

	sevGuestDev = "/dev/sev-guest"
	tdxGuestDev = "/dev/tdx_guest"
	sevHostDev  = "/dev/sev"
)

// DetectCapability reports what can protect a key on this machine.
//
// Confidential computing is checked first and deliberately: our own sealed
// infrastructure has no TPM at all, so a TPM-first check that gave up on
// finding none would reject the one environment we call the strongest.
func DetectCapability() Capability {
	if c, found := detectConfidentialGuest(); found {
		return c
	}
	return detectTPM2()
}

// detectConfidentialGuest reports whether we are running INSIDE a sealed VM.
//
// The device node is proof rather than a hint: the kernel only registers
// /dev/sev-guest when the platform actually reports an SNP guest, so it cannot
// exist on a machine that is not one. Its ABSENCE proves much less — as we
// found by measuring, a genuinely sealed guest whose image was missing the
// driver had no node at all, so absence is "we cannot attest", never "this is
// not sealed".
func detectConfidentialGuest() (Capability, bool) {
	for _, d := range []struct {
		path string
		kind Kind
	}{
		{sevGuestDev, KindSEVSNP},
		{tdxGuestDev, KindTDX},
	} {
		info, err := os.Stat(d.path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeDevice == 0 {
			// A regular file where a device should be is not a sealed guest,
			// and treating it as one would be trivially forgeable.
			return Capability{
				Status: Unknown,
				Reason: "confidential_device_not_a_device_node",
				Detail: d.path + " exists but is not a character device",
			}, true
		}

		f, err := os.OpenFile(d.path, os.O_RDWR, 0)
		if err == nil {
			f.Close()
			return Capability{Status: Usable, Kind: d.kind, Reason: "attested_execution"}, true
		}
		if errors.Is(err, os.ErrPermission) {
			// The hardware is here and this process cannot reach it. On stock
			// images the node is root-only, so this is the expected state for
			// an unprivileged agent rather than a fault.
			return Capability{
				Status: Present,
				Kind:   d.kind,
				Reason: "permission_denied",
				Detail: err.Error(),
			}, true
		}
		return Capability{
			Status: Unknown,
			Kind:   d.kind,
			Reason: "confidential_device_unusable",
			Detail: err.Error(),
		}, true
	}
	return Capability{}, false
}

// SealedHostCapable reports whether this machine can LAUNCH sealed guests.
//
// Deliberately not part of DetectCapability, and deliberately not a Capability:
// it is a fact about what this host can offer other people, and says nothing
// about protecting a key here. Conflating the two would let a provisioning host
// claim the protection it sells rather than provides.
func SealedHostCapable() bool {
	info, err := os.Stat(sevHostDev)
	return err == nil && info.Mode()&os.ModeDevice != 0
}

// detectTPM2 asks the three questions in the order that keeps them separable:
// does the kernel know about a TPM, is it version 2, and can we use it.
func detectTPM2() Capability {
	version, chips, sysfsErr := tpmSysfsVersion()

	switch {
	case sysfsErr != nil:
		return Unproven("tpm_subsystem_unreadable",
			"could not read "+tpmClassDir+": "+sysfsErr.Error())

	case chips == 0:
		// No chip enumerated. Whether that means absent, disabled in firmware,
		// or a driver that never loaded is NOT separable from user space, so
		// the message says what to check rather than pretending to know.
		if _, err := os.Stat(acpiTPM2Table); err == nil {
			return Capability{
				Status: Unknown,
				Reason: "tpm_advertised_by_firmware_but_not_enumerated",
				Detail: "the firmware lists a TPM2 ACPI table but the kernel enumerated no chip — likely disabled in UEFI, or the driver did not load",
			}
		}
		return Capability{
			Status: Absent,
			Reason: "no_tpm_chip",
			Detail: "no chip under " + tpmClassDir + " and no TPM2 ACPI table; if this machine has a TPM, check whether it is enabled in UEFI firmware",
		}

	case version == 1:
		// A real, positive finding: there is a TPM and it is not one we accept.
		return Capability{
			Status: Absent,
			Kind:   KindNone,
			Reason: "tpm_1_2_not_supported",
			Detail: "a TPM 1.2 was found; hardware key protection requires TPM 2.0",
		}

	case version != 2:
		return Unproven("tpm_version_unreadable",
			fmt.Sprintf("a TPM chip is present but its version could not be read (got %d)", version))
	}

	// A TPM 2.0 is here. Everything below is about reachability, and every
	// branch already knows the hardware exists — so none of them may say absent.
	info, err := os.Stat(tpmResourceMgr)
	if err != nil {
		if _, rawErr := os.Stat(tpmRaw); rawErr == nil {
			// Never opened. /dev/tpm0 is single-holder exclusive, so probing it
			// would lock out systemd-cryptenroll, IMA and anything else using
			// the chip — a detector must not cost the machine its TPM.
			return Capability{
				Status: Present, Kind: KindTPM2,
				Reason: "no_resource_manager",
				Detail: "only the exclusive " + tpmRaw + " is present; the kernel resource manager is missing, so this cannot be shared safely",
			}
		}
		return Capability{
			Status: Present, Kind: KindTPM2,
			Reason: "device_node_missing",
			Detail: "sysfs reports a TPM 2.0 but no device node exists — typical of a container without passthrough",
		}
	}
	if info.Mode()&os.ModeDevice == 0 {
		return Capability{
			Status: Unknown, Kind: KindTPM2,
			Reason: "tpm_node_not_a_device",
			Detail: tpmResourceMgr + " is not a character device",
		}
	}

	f, err := os.OpenFile(tpmResourceMgr, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			// The case this whole file exists for. sysfs already told us there
			// is a TPM 2.0 here, so we report it as present-and-unreachable —
			// with the remedy, because the remedy is usually one group.
			return Capability{
				Status: Present, Kind: KindTPM2,
				Reason: "permission_denied",
				Detail: "a TPM 2.0 is present but this process cannot open " + tpmResourceMgr +
					" — usually fixed by adding the user to the tss group: " + err.Error(),
			}
		}
		return Capability{
			Status: Present, Kind: KindTPM2,
			Reason: "tpm_open_failed",
			Detail: err.Error(),
		}
	}
	f.Close()

	return Capability{Status: Usable, Kind: KindTPM2, Reason: "tpm2_reachable"}
}

// tpmSysfsVersion reads what the kernel says, from paths that are world-readable
// by design — which is why a positive TPM 2.0 finding survives having no access
// to the device node at all.
func tpmSysfsVersion() (version, chips int, err error) {
	entries, err := os.ReadDir(tpmClassDir)
	if err != nil {
		if os.IsNotExist(err) {
			// The subsystem itself is absent: no TPM driver at all. Reported as
			// zero chips rather than as an error, so the caller's absent branch
			// can weigh it against the ACPI table.
			return 0, 0, nil
		}
		return 0, 0, err
	}

	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "tpm") {
			continue
		}
		chips++
		raw, rerr := os.ReadFile(filepath.Join(tpmClassDir, e.Name(), "tpm_version_major"))
		if rerr != nil {
			// Present on both 1.2 and 2.0 chips, so a missing file means a
			// kernel too old to publish it — not a version we can assume.
			continue
		}
		switch strings.TrimSpace(string(raw)) {
		case "2":
			return 2, chips, nil
		case "1":
			version = 1
		}
	}
	return version, chips, nil
}
