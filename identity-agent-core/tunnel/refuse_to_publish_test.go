package tunnel

import "testing"

// An operator can say "do not publish this agent".
//
// Before this, they could not. DefaultConfig read two token variables and, when
// neither was set, returned a Grape ID tunnel — so an agent put itself on the
// public internet within seconds of first start and there was no variable that
// said otherwise. TUNNEL_PROVIDER looked like it should work and was read by
// nothing.
//
// That mattered more than it sounds: an agent nobody has claimed yet is one
// anybody could claim, so publishing one before its owner has it is a window
// worth being able to close.
func TestAnAgentCanBeToldNotToPublishItself(t *testing.T) {
	// Set alongside a token, because the token branches came first and would
	// otherwise win. Somebody who has ngrok configured and still says "none"
	// means none.
	t.Setenv("NGROK_AUTHTOKEN", "a-token-that-must-not-win")
	t.Setenv("TUNNEL_PROVIDER", "none")

	if got := DefaultConfig().Provider; got != ProviderNone {
		t.Fatalf("asked for no tunnel, got %q — the agent would publish itself anyway", got)
	}
}

func TestTheRefusalIsForgivingAboutHowItIsWritten(t *testing.T) {
	// An operator typing this into a unit file or a shell should not have to
	// guess at casing or trailing whitespace to keep an agent off the internet.
	for _, spelling := range []string{"none", "None", "NONE", "  none  ", "none\n"} {
		t.Setenv("TUNNEL_PROVIDER", spelling)
		if got := DefaultConfig().Provider; got != ProviderNone {
			t.Errorf("TUNNEL_PROVIDER=%q gave %q, want none", spelling, got)
		}
	}
}

// Stating any provider explicitly works, so the variable is not a special case
// with one usable value.
func TestAProviderCanBeNamedOutright(t *testing.T) {
	for _, tc := range []struct {
		set  string
		want ProviderType
	}{
		{"ngrok", ProviderNgrok},
		{"cloudflare", ProviderCloudflare},
		{"grapeid", ProviderGrapeID},
	} {
		t.Setenv("TUNNEL_PROVIDER", tc.set)
		if got := DefaultConfig().Provider; got != tc.want {
			t.Errorf("TUNNEL_PROVIDER=%q gave %q, want %q", tc.set, got, tc.want)
		}
	}
}

// Saying nothing must behave exactly as it did before, or this becomes a
// silent change to every existing deployment rather than a new choice.
func TestSayingNothingChangesNothing(t *testing.T) {
	t.Setenv("TUNNEL_PROVIDER", "")
	t.Setenv("CLOUDFLARE_TUNNEL_TOKEN", "")
	t.Setenv("NGROK_AUTHTOKEN", "a-token")

	if got := DefaultConfig().Provider; got != ProviderNgrok {
		t.Fatalf("with no explicit provider and an ngrok token, got %q, want ngrok", got)
	}
}

// An unrecognised value must not quietly mean "none" — that would turn a typo
// into an agent nobody can reach, which is as confusing as the bug this fixes.
func TestATypoFallsThroughRatherThanSilencingTheAgent(t *testing.T) {
	t.Setenv("TUNNEL_PROVIDER", "nonw")
	t.Setenv("NGROK_AUTHTOKEN", "a-token")

	if got := DefaultConfig().Provider; got != ProviderNgrok {
		t.Fatalf("a misspelt provider gave %q; it should fall through to the normal detection", got)
	}
}
