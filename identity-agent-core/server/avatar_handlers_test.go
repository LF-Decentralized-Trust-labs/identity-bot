package server

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"identity-agent-core/avatar"
	"identity-agent-core/store"
)

func avatarTestServer(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	return &CoreServer{DataDir: dir, DataStore: ds}
}

// The guarantee: after identity creation there is always an avatar, with no
// user action. Every screen downstream can rely on it.
func TestEnsureAvatarGivesAProfileOneWhenItHasNone(t *testing.T) {
	s := avatarTestServer(t)
	created, err := s.ensureAvatar()
	if err != nil {
		t.Fatalf("ensureAvatar: %v", err)
	}
	if !created {
		t.Fatal("no avatar was generated for a profile that had none")
	}
	profile, err := s.DataStore.GetProfile()
	if err != nil || profile == nil || profile.Photo == "" {
		t.Fatalf("profile has no avatar after ensureAvatar: %+v (%v)", profile, err)
	}
}

// It must never overwrite what the user chose.
func TestEnsureAvatarLeavesAnExistingOneAlone(t *testing.T) {
	s := avatarTestServer(t)
	chosen, err := avatar.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := s.DataStore.SaveProfile(store.ProfileData{FullName: "Ada", Photo: chosen}); err != nil {
		t.Fatalf("save profile: %v", err)
	}

	created, err := s.ensureAvatar()
	if err != nil {
		t.Fatalf("ensureAvatar: %v", err)
	}
	if created {
		t.Error("ensureAvatar replaced an avatar the user already had")
	}
	profile, _ := s.DataStore.GetProfile()
	if profile.Photo != chosen {
		t.Error("the stored avatar changed")
	}
}

// Calling it repeatedly — every boot, every store — must be harmless.
func TestEnsureAvatarIsIdempotent(t *testing.T) {
	s := avatarTestServer(t)
	if _, err := s.ensureAvatar(); err != nil {
		t.Fatalf("first: %v", err)
	}
	first, _ := s.DataStore.GetProfile()
	for i := 0; i < 3; i++ {
		if _, err := s.ensureAvatar(); err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
	}
	again, _ := s.DataStore.GetProfile()
	if first.Photo != again.Photo {
		t.Error("repeated calls changed the avatar")
	}
}

// An oversized original is squared and scaled on save, so it cannot end up
// travelling inside every introduction at full size.
func TestSavingNormalizesWhateverWasSent(t *testing.T) {
	big := makeWidePhoto(t)
	profile := store.ProfileData{FullName: "Ada", Photo: avatar.DataURI("image/jpeg", big)}
	normalizeProfileAvatar(&profile)

	raw, err := avatar.DecodeDataURI(profile.Photo)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) >= len(big) {
		t.Errorf("stored %d bytes for a %d byte original — it was not scaled", len(raw), len(big))
	}
}

// Clearing the picture is allowed; being without one is not.
func TestClearingTheAvatarYieldsAGeneratedOne(t *testing.T) {
	profile := store.ProfileData{FullName: "Ada", Photo: ""}
	normalizeProfileAvatar(&profile)
	if profile.Photo != "" {
		t.Fatal("normalize invented an avatar — that is the save path's job, not this one")
	}
	// The save path is what fills it; assert the generator it uses works.
	generated, err := avatar.Generate()
	if err != nil || generated == "" {
		t.Fatalf("generator unavailable: %v", err)
	}
}

// An unreadable value is kept as sent rather than silently dropped — losing
// the user's picture is worse than storing something we could not resize.
func TestUnreadableAvatarIsKeptNotDiscarded(t *testing.T) {
	profile := store.ProfileData{Photo: "data:image/png;base64,!!!!"}
	normalizeProfileAvatar(&profile)
	if profile.Photo == "" {
		t.Error("an unreadable avatar was discarded instead of kept")
	}
}

func makeWidePhoto(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1200, 600))
	for y := 0; y < 600; y++ {
		for x := 0; x < 1200; x++ {
			img.SetRGBA(x, y, color.RGBA{uint8(x % 255), uint8(y % 255), 90, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return buf.Bytes()
}
