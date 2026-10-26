package authprovider

import (
	"testing"
	"time"
)

func TestTheBadgeIsDerivedFromTheScore(t *testing.T) {
	for score, want := range map[int]string{
		100: "green", 80: "green", 79: "amber", 40: "amber", 39: "red", 0: "red",
	} {
		if got := BadgeForScore(score); got != want {
			t.Errorf("score %d shows %q, want %q", score, got, want)
		}
		if got := LevelForScore(score).Badge(); got != want {
			t.Errorf("score %d names a level shown %q, want %q", score, got, want)
		}
	}
}

func TestThePlaceholderSaysEightyAndSaysItIsAPlaceholder(t *testing.T) {
	now := time.Now()
	got := UntilHumanAuthenticationIsBuilt(now)
	if !got.Measured || got.Score != 80 || got.Provider != PlaceholderProvider {
		t.Fatalf("the placeholder answered %+v", got)
	}
	if !got.At.Equal(now.UTC()) {
		t.Fatalf("the placeholder is not about now: %v", got.At)
	}
}
