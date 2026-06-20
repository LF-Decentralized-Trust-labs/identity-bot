package login

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"identity-agent-core/m63"
)

func nfc(s string) string {
	// Go strings are UTF-8; NFC normalization deferred — sufficient for steel thread.
	return s
}

func jsonField(key string, value interface{}) string {
	if value == nil {
		return ""
	}
	b, _ := json.Marshal(value)
	return fmt.Sprintf(`"%s":%s`, key, string(b))
}

func canonicalChallengeBody(c ChallengeBundle) string {
	parts := []string{
		jsonField("v", c.V),
		jsonField("t", c.T),
		jsonField("site_aid", nfc(c.SiteAID)),
		jsonField("site_oobi", nfc(c.SiteOOBI)),
		jsonField("audience", nfc(c.Audience)),
		jsonField("nonce", c.Nonce),
		jsonField("dt", c.Dt),
		jsonField("expiry", c.Expiry),
		jsonField("requested_disclosures", c.RequestedDisclosures),
		jsonField("requested_credentials", c.RequestedCredentials),
	}
	if c.RequestedScore != nil {
		parts = append(parts, jsonField("requested_score", c.RequestedScore))
	}
	parts = append(parts,
		jsonField("callback_url", nfc(c.CallbackURL)),
		jsonField("session_token", c.SessionToken),
	)
	return "{" + strings.Join(filterEmpty(parts), ",") + "}"
}

func canonicalAssertionBody(a Assertion) string {
	parts := []string{
		jsonField("v", a.V),
		jsonField("t", a.T),
		jsonField("d", a.D),
		jsonField("i", nfc(a.I)),
		jsonField("relationship_aid_oobi", nfc(a.RelationshipAIDOOBI)),
		jsonField("audience", nfc(a.Audience)),
		jsonField("nonce", a.Nonce),
		jsonField("dt", a.Dt),
		jsonField("disclosures", a.Disclosures),
		jsonField("presented_acdcs", a.PresentedACDCs),
	}
	if a.CustomData != nil {
		parts = append(parts, jsonField("custom_data", a.CustomData))
	}
	if a.PKEL != "" {
		parts = append(parts, jsonField("p_kel", a.PKEL))
	}
	return "{" + strings.Join(filterEmpty(parts), ",") + "}"
}

func assertionDigest(a Assertion) (string, error) {
	a.D = ""
	body := canonicalAssertionBody(a)
	return m63.Blake3QB64([]byte(body))
}

func filterEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func rfc3339UTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func parseRFC3339(s string) (time.Time, error) {
	if !utf8.ValidString(s) {
		return time.Time{}, fmt.Errorf("invalid dt")
	}
	return time.Parse(time.RFC3339, s)
}