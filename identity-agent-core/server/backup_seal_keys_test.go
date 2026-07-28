package server

import (
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

const sealTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func seedOnDisk(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	seed, err := backup.MnemonicToBIP39Seed(sealTestMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := secureenclave.StoreRootSeed(dir, seed); err != nil {
		t.Fatalf("store root seed: %v", err)
	}
	return &CoreServer{DataDir: dir}
}

// What the owner sends must be the PUBLIC half and nothing else. Sending the
// private half would hand the adopted device the ability to read every archive
// it writes, which is the whole thing this avoids.
func TestOwnerPublishesOnlyThePublicHalf(t *testing.T) {
	s := seedOnDisk(t)

	keys, err := s.ownerBackupSealPublicKeys()
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected one key, got %d", len(keys))
	}

	seed, _ := backup.MnemonicToBIP39Seed(sealTestMnemonic, "")
	priv, pub, err := backup.DeriveSealKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0] != backup.EncodeB64(pub) {
		t.Fatal("the key sent is not this owner's sealing public key")
	}
	if keys[0] == backup.EncodeB64(priv) {
		t.Fatal("the private half was sent")
	}
}

// A device with no root seed has nothing to derive from, and must say so
// rather than publish something useless.
func TestDerivingWithoutARootSeedFails(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if _, err := s.ownerBackupSealPublicKeys(); err == nil {
		t.Fatal("a device with no root seed produced a recovery key")
	}
}

// A malformed key must be refused when it arrives. Stored and trusted, it
// becomes an archive nobody can open — discovered on the one day it matters.
func TestMalformedRecoveryKeysAreRefused(t *testing.T) {
	cases := map[string][]string{
		"not base64":     {"!!!! not base64 !!!!"},
		"wrong length":   {backup.EncodeB64([]byte("too short"))},
		"empty list":     {},
		"one bad of two": {backup.EncodeB64(make([]byte, backup.X25519KeyLen)), "!!!!"},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			s := &CoreServer{DataDir: t.TempDir()}
			if err := s.recordBackupSealKeys(keys); err == nil {
				t.Fatal("a bad recovery key was accepted")
			}
		})
	}
}

// Validation happens before anything is written, so a list with one bad key
// leaves no partial state behind.
func TestABadKeyStoresNothing(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	good := backup.EncodeB64(make([]byte, backup.X25519KeyLen))

	if err := s.recordBackupSealKeys([]string{good, "!!!!"}); err == nil {
		t.Fatal("expected refusal")
	}
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		return // no config written at all is the correct outcome too
	}
	if len(cfg.SealToPublicKeysB64) != 0 {
		t.Fatalf("a refused list still stored %d keys", len(cfg.SealToPublicKeysB64))
	}
}

// The round trip the adoption depends on: what one side derives, the other
// side accepts and stores.
func TestWhatTheOwnerSendsTheDeviceAccepts(t *testing.T) {
	owner := seedOnDisk(t)
	keys, err := owner.ownerBackupSealPublicKeys()
	if err != nil {
		t.Fatal(err)
	}

	device := &CoreServer{DataDir: t.TempDir()}
	if err := device.recordBackupSealKeys(keys); err != nil {
		t.Fatalf("the device refused what the owner sent: %v", err)
	}

	cfg, err := device.backupService().LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SealToPublicKeysB64) != 1 || cfg.SealToPublicKeysB64[0] != keys[0] {
		t.Fatal("the device stored something other than what the owner sent")
	}

	// And the point of it all: the device can now write an archive that only
	// the owner's phrase opens.
	raw, err := backup.DecodeB64(cfg.SealToPublicKeysB64[0])
	if err != nil {
		t.Fatal(err)
	}
	collector := &backup.Collector{DataDir: t.TempDir()}
	result, err := collector.CreateArchive(
		backup.CollectOptions{Tiers: []string{backup.TierCritical}},
		backup.ExportRequest{
			Bundle: &backup.PayloadBundle{
				Ordered: []backup.PayloadSection{{Name: "test", Data: []byte("company data")}},
			},
			SealToPublicKeys: [][]byte{raw},
		},
	)
	if err != nil {
		t.Fatalf("the device could not back up with the key it was given: %v", err)
	}
	if _, _, err := backup.OpenArchive(result.Bytes, backup.OpenRequest{Mnemonic: sealTestMnemonic}); err != nil {
		t.Fatalf("the owner's phrase did not open what the device wrote: %v", err)
	}

	for _, slot := range result.Manifest.KeySlots {
		if slot.Type == backup.SlotSeedHD {
			t.Fatal("the device wrote a seed slot, so it must have been given a seed")
		}
	}
}

// An adoption that carries no recovery key still succeeds — the device is
// legitimately owned — but it must be obvious in the log, because such a device
// cannot back up without being handed a phrase later.
func TestAdoptionWithoutARecoveryKeyIsNotSilent(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	err := s.recordBackupSealKeys(nil)
	if err == nil {
		t.Fatal("an empty list should be refused rather than stored as success")
	}
	if !strings.Contains(err.Error(), "no recovery keys") {
		t.Fatalf("unclear error for the case that matters: %v", err)
	}
}
