package messagingkeys

import (
	"encoding/json"
	"testing"

	"identity-agent-core/iacrypto"
)

// A seal judged one way by the key readers in iacrypto and another by
// SealsAmong would let a keyset be seen by one and missed by the other. Every
// shape here must get the same verdict from both.
func TestSealsAmongAgreesWithIacryptoOnEverySeal(t *testing.T) {
	suite := iacrypto.CipherSuiteIAHybrid1
	cases := []struct {
		name, raw string
		want      bool
	}{
		{"the suite", `{"ia":"` + suite + `"}`, true},
		{"another suite", `{"ia":"other"}`, false},
		{"no suite", `{"d":"x"}`, false},
		{"suite is not a string", `{"ia":1}`, false},
		{"member name other case", `{"IA":"` + suite + `"}`, false},
		{"suite in other case", `{"ia":"ia-hybrid-1"}`, false},
		{"not an object", `"` + suite + `"`, false},
		{"null", `null`, false},
	}
	for _, c := range cases {
		name, raw, want := c.name, c.raw, c.want
		var m map[string]interface{}
		if (json.Unmarshal([]byte(raw), &m) == nil && iacrypto.IsKeysetSeal(m)) != want {
			t.Errorf("%s: iacrypto.IsKeysetSeal disagrees with expected %v", name, want)
		}
		got := len(SealsAmong([]json.RawMessage{json.RawMessage(raw)})) == 1
		if got != want {
			t.Errorf("%s: SealsAmong=%v, want %v", name, got, want)
		}
	}
}
