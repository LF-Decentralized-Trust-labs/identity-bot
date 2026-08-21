package backup

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func anArchive(t *testing.T) *ArchiveFile {
	t.Helper()
	return &ArchiveFile{
		Manifest:   NewManifest("EMyIdentity", []string{TierCritical}, "full"),
		Ciphertext: []byte("the encrypted body of a backup"),
	}
}

func theOwnersSeed(t *testing.T) []byte {
	t.Helper()
	seed, err := MnemonicToBIP39Seed(wordsForTest, "")
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// Somebody else's archive, sealed to this owner, must not pass as theirs.
//
// This is the attack the whole file exists for. Sealing needs a public key and
// public keys are public, so anybody can encrypt an archive TO an owner — and
// opening it proves only that. A restore then writes every file it carries
// back to its path, so a substituted archive is attacker-chosen content
// written into somebody's agent.
func TestAnArchiveWrittenByAStrangerIsRefused(t *testing.T) {
	seed := theOwnersSeed(t)

	// What an attacker can make: a well-formed archive, correctly addressed.
	forged := anArchive(t)
	other := make([]byte, 64)
	rand.Read(other)
	if err := SignWithSeed(forged, other); err != nil {
		t.Fatal(err)
	}

	err := CheckWhoWroteIt(forged, seed, nil)
	if err == nil {
		t.Fatal("an archive written by somebody else passed as this owner's")
	}
	if !strings.Contains(err.Error(), "may have been replaced") {
		t.Fatalf("refused without saying what it means: %v", err)
	}
}

// The owner's own archive passes.
func TestAnOwnersOwnArchivePasses(t *testing.T) {
	seed := theOwnersSeed(t)
	arch := anArchive(t)
	if err := SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}
	if err := CheckWhoWroteIt(arch, seed, nil); err != nil {
		t.Fatalf("an archive this owner wrote was refused: %v", err)
	}
}

// The mark covers the cleartext manifest, not only the body.
//
// Signing the ciphertext alone would leave the section digests, the key slots
// and the bootstrap envelope free for anybody to edit — all of which sit in
// the manifest, in the clear.
func TestEditingTheCleartextManifestBreaksTheMark(t *testing.T) {
	seed := theOwnersSeed(t)
	arch := anArchive(t)
	if err := SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}

	for _, edit := range []struct {
		what string
		do   func(*Manifest)
	}{
		{"the identity it claims to be", func(m *Manifest) { m.IdentityAID = "ESomebodyElse" }},
		{"a section digest", func(m *Manifest) {
			m.Sections = append(m.Sections, SectionMeta{Name: "x", DigestBlake3QB64: "y"})
		}},
		{"the bootstrap envelope", func(m *Manifest) { m.BootstrapB64 = EncodeB64([]byte("swapped")) }},
		{"a key slot", func(m *Manifest) { m.KeySlots = append(m.KeySlots, KeySlot{Type: SlotSeedHD}) }},
	} {
		tampered := *arch
		tampered.Manifest = arch.Manifest
		edit.do(&tampered.Manifest)
		if err := CheckWhoWroteIt(&tampered, seed, nil); err == nil {
			t.Fatalf("editing %s left the mark intact", edit.what)
		}
	}
}

// Editing the body breaks it too.
func TestEditingTheBodyBreaksTheMark(t *testing.T) {
	seed := theOwnersSeed(t)
	arch := anArchive(t)
	if err := SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}
	arch.Ciphertext = append(arch.Ciphertext, 'x')
	if err := CheckWhoWroteIt(arch, seed, nil); err == nil {
		t.Fatal("the body was changed and the mark still passed")
	}
}

// A machine-signed archive means nothing without a key to check it against.
//
// A signature verified with the key that came WITH it proves only that the
// writer can sign their own work, which every attacker can.
func TestAMachineSignatureNeedsAKnownKeyToMeanAnything(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	arch := anArchive(t)
	if err := SignWithMachineKey(arch, priv); err != nil {
		t.Fatal(err)
	}

	// Checked against nothing: refused, with the reason.
	err = CheckWhoWroteIt(arch, nil, nil)
	if err == nil {
		t.Fatal("a machine-signed archive passed with nothing to check it against")
	}
	if !strings.Contains(err.Error(), "no record of which machines") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// And says what to do about it, because a rebuilt machine having no such
	// record is the ordinary state rather than a fault.
	if !strings.Contains(err.Error(), "Restore this identity's own backup first") {
		t.Fatalf("the refusal does not say what to do: %v", err)
	}

	// Checked against the key recorded when that machine was paired: passes.
	if err := CheckWhoWroteIt(arch, nil, pub); err != nil {
		t.Fatalf("the machine that was paired could not prove it wrote this: %v", err)
	}

	// A different machine's archive, presented as that one's: refused.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub
	impostor := anArchive(t)
	if err := SignWithMachineKey(impostor, otherPriv); err != nil {
		t.Fatal(err)
	}
	if err := CheckWhoWroteIt(impostor, nil, pub); err == nil {
		t.Fatal("an archive signed by a different machine passed as the paired one's")
	}
}

// An archive that says nothing is its own answer, distinguishable from a wrong
// mark — because one is an old archive and the other is somebody's substitute.
func TestSayingNothingIsDifferentFromSayingSomethingWrong(t *testing.T) {
	seed := theOwnersSeed(t)
	silent := anArchive(t)
	if err := CheckWhoWroteIt(silent, seed, nil); !errors.Is(err, ErrArchiveUnattributed) {
		t.Fatalf("an unattributed archive was not reported as such: %v", err)
	}

	wrong := anArchive(t)
	other := make([]byte, 64)
	rand.Read(other)
	SignWithSeed(wrong, other)
	if err := CheckWhoWroteIt(wrong, seed, nil); errors.Is(err, ErrArchiveUnattributed) {
		t.Fatal("a WRONG mark was reported as a missing one, so it could be waved through")
	}
}

// A file whose header decodes right but reads wrong is refused.
//
// The mark is computed over the decoded manifest, so two files that decode
// alike and differ on disk both verified. One carries a field the decoder
// drops; one carries a duplicate key whose FIRST copy is a lie, so a parser
// taking the first reads something the mark never covered. Any digest,
// deduplication or same-archive comparison was defeated while the check said
// yes.
func TestAFileThatDecodesRightAndReadsWrongIsRefused(t *testing.T) {
	seed := theOwnersSeed(t)
	arch := anArchive(t)
	if err := SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}
	good, err := EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	// It passes as written.
	decoded, err := DecodeArchive(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckWhoWroteIt(decoded, seed, nil); err != nil {
		t.Fatalf("the archive as written was refused: %v", err)
	}

	canonical, err := json.Marshal(arch.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, tampered := range []struct {
		what     string
		manifest []byte
	}{
		{
			"a field the decoder drops",
			append([]byte(`{"a_field_from_the_future":"anything",`), canonical[1:]...),
		},
		{
			"a duplicate key whose first copy is a lie",
			append([]byte(`{"identity_aid":"ESomebodyElse",`), canonical[1:]...),
		},
	} {
		rebuilt := rebuildArchive(t, tampered.manifest, arch.Ciphertext)
		again, err := DecodeArchive(rebuilt)
		if err != nil {
			// Refused at the door is also a pass.
			continue
		}
		if err := CheckWhoWroteIt(again, seed, nil); err == nil {
			t.Fatalf("%s produced a different file that verified identically", tampered.what)
		}
	}
}

// rebuildArchive frames a manifest and a body the way a file is framed.
func rebuildArchive(t *testing.T, manifest, ciphertext []byte) []byte {
	t.Helper()
	out := append([]byte(IABMagic), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(manifest)))
	out = append(out, manifest...)
	return append(out, ciphertext...)
}
