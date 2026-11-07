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
	cases := map[string]string{
		"the suite":              `{"ia":"` + suite + `"}`,
		"another suite":          `{"ia":"other"}`,
		"no suite":               `{"d":"x"}`,
		"suite is not a string":  `{"ia":1}`,
		"member name other case": `{"IA":"` + suite + `"}`,
		"not an object":          `"` + suite + `"`,
		"null":                   `null`,
	}
	for name, raw := range cases {
		var m map[string]interface{}
		want := json.Unmarshal([]byte(raw), &m) == nil && iacrypto.IsKeysetSeal(m)
		got := len(SealsAmong([]json.RawMessage{json.RawMessage(raw)})) == 1
		if got != want {
			t.Errorf("%s: SealsAmong=%v but iacrypto.IsKeysetSeal=%v", name, got, want)
		}
		if name == "member name other case" && got {
			t.Errorf("a differently-cased member name must not mark a keyset seal")
		}
	}
}
