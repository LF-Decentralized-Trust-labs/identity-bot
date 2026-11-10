package login

import (
	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
)

// BoundCredentials are the credentials an assertion presents, as a policy gate
// or a website's server reads them (ADR-071). The assertion signs a digest for
// each; the credentials arrive beside it, unsigned, so one counts only if its
// SAID is a digest the assertion names and the body it carries has that SAID. A
// credential posted but not named is left out, and a digest with no credential
// posted presents nothing. An assertion in the older form carries the
// credentials whole, and they are returned as they always were.
//
// The TypeScript package @identity-agent/login-verify has the same rule
// (boundCredentials); the sign_in_posts vectors hold the two together.
func BoundCredentials(presented []interface{}, posted []PresentedCredential) []interface{} {
	named := map[string]bool{}
	var out []interface{}
	for _, p := range presented {
		switch v := p.(type) {
		case string:
			named[v] = true
		default:
			out = append(out, p)
		}
	}
	for _, c := range posted {
		if !named[c.SAID] {
			continue
		}
		raw, err := iacrypto.DecodeBase64(c.AcdcJsonB64)
		if err != nil {
			continue
		}
		cred, err := keri.VerifyCredential(raw)
		if err != nil || cred.SAID != c.SAID {
			continue
		}
		out = append(out, map[string]interface{}{
			"said":              c.SAID,
			"schema_said":       cred.SchemaSAID,
			"issuer_aid":        cred.Issuer,
			"holder_aid":        c.HolderAID,
			"status":            c.Status,
			"acdc_json_b64":     c.AcdcJsonB64,
			"pres_said_b64":     c.PresSaidB64,
			"cesr_sig":          c.CesrSig,
			"holder_public_key": c.HolderPublicKey,
		})
	}
	return out
}
