package activitylog

import (
	"strings"
	"testing"
)

// ── argument preview ────────────────────────────────────────────────────────
//
// The preview exists so a person reading the log can see what a capability was
// asked to do. That is only safe if it cannot become a place secrets come to rest,
// which is what these tests pin.

func TestPreviewArgsRedactsSecretsByKey(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string // substring that must appear
		deny string // substring that must NOT appear
	}{
		{"api_key", `{"api_key":"ghp_realtokenvalue"}`, "api_key=[redacted]", "ghp_realtokenvalue"},
		{"password", `{"password":"hunter2"}`, "password=[redacted]", "hunter2"},
		{"authorization", `{"authorization":"Bearer abc"}`, "authorization=[redacted]", "Bearer abc"},
		{"mixed case", `{"API_Key":"zzz"}`, "API_Key=[redacted]", "zzz"},
		{"embedded", `{"github_token":"zzz"}`, "github_token=[redacted]", "zzz"},
		{"passphrase", `{"passphrase":"correct horse"}`, "passphrase=[redacted]", "correct horse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := previewArgs([]byte(tc.args))
			if !strings.Contains(got, tc.want) {
				t.Errorf("preview %q: want substring %q", got, tc.want)
			}
			if strings.Contains(got, tc.deny) {
				t.Fatalf("preview LEAKED a secret value: %q", got)
			}
		})
	}
}

func TestPreviewArgsShowsOrdinaryValues(t *testing.T) {
	got := previewArgs([]byte(`{"repo":"strategy","task":"add the linter"}`))
	if !strings.Contains(got, "repo=strategy") || !strings.Contains(got, "task=add the linter") {
		t.Fatalf("ordinary arguments should be readable, got %q", got)
	}
}

func TestPreviewArgsIsStable(t *testing.T) {
	// Two identical calls must read identically in the log, so keys are sorted
	// rather than left in Go's randomised map order.
	args := []byte(`{"z":"1","a":"2","m":"3"}`)
	first := previewArgs(args)
	for i := 0; i < 20; i++ {
		if got := previewArgs(args); got != first {
			t.Fatalf("preview is not stable: %q != %q", got, first)
		}
	}
	if first != "a=2 m=3 z=1" {
		t.Fatalf("want sorted keys, got %q", first)
	}
}

func TestPreviewArgsDoesNotDescendIntoNestedValues(t *testing.T) {
	// A nested object is the likeliest place for a secret to sit under a name the
	// blocklist has never seen, so nothing nested is ever rendered.
	got := previewArgs([]byte(`{"cfg":{"innocuous_name":"sk-live-secret"},"repo":"x"}`))
	if strings.Contains(got, "sk-live-secret") {
		t.Fatalf("preview descended into a nested object and leaked: %q", got)
	}
	if !strings.Contains(got, "cfg=[object]") {
		t.Fatalf("want nested value summarised, got %q", got)
	}
}

func TestPreviewArgsTruncatesAndFlattens(t *testing.T) {
	long := strings.Repeat("a", previewMaxValue+50)
	got := previewArgs([]byte(`{"task":"` + long + `"}`))
	if len(got) > previewMaxValue+40 {
		t.Fatalf("preview not truncated: %d chars", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncation should be visible, got %q", got)
	}
	multi := previewArgs([]byte(`{"task":"line one\nline two"}`))
	if strings.Contains(multi, "\n") {
		t.Fatalf("preview must stay on one line, got %q", multi)
	}
}

func TestPreviewArgsHandlesNonObjects(t *testing.T) {
	// Not every capability takes a JSON object. Those still get a hash; they just
	// get no preview, which must not panic or produce noise.
	for _, in := range []string{"", "not json at all", `["a","b"]`, `42`} {
		if got := previewArgs([]byte(in)); got != "" {
			t.Errorf("input %q: want empty preview, got %q", in, got)
		}
	}
}
