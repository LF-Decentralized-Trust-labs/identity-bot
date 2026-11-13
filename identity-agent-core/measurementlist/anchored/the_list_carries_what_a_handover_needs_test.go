package anchored

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"identity-agent-core/measurementlist"
)

func v2Images(extra string) string {
	return fmt.Sprintf(`{"organisation":[{"image":"org-v2","measurement":"%s","computed_from":{"ovmf_sha256":"%064x","vcpus":1,"cpu_model":"EPYC-v4","cmdline_sha256":"%064x"},"valid_from":"2026-11-01T00:00:00Z","valid_until":null%s}]}`,
		meas(7), 1, 2, extra)
}

// The security version, the environment, SMT and the retirement of an entry are
// part of the anchored content, read by the code that reads a signed list's.
func TestAnAnchoredListCarriesTheSecurityVersionAndRetirement(t *testing.T) {
	p := onekey(t)
	p.foundRegistry()
	p.issue(listSpec{sequence: 3, expires: t0.Add(60 * 24 * time.Hour), extra: `"list_version":2,`,
		images: v2Images(`,"environment":"production","svn":6,"smt":true,"retired":{"kind":"update","at":"2026-11-10T00:00:00Z","source_until":"2026-12-01T00:00:00Z"}`)})
	res := accept(t, p, Floors{})
	e := res.List.Images["organisation"][0]
	if !e.HasSVN || e.SVN != 6 || e.Environment != "production" || !e.SMT || e.Retired == nil || e.Retired.Kind != measurementlist.RetiredForUpdate {
		t.Fatalf("the entry read as %+v", e)
	}
}

func TestAnAnchoredListsHandoverFieldsAreReadStrictly(t *testing.T) {
	base := `,"environment":"production","svn":6,"smt":true`
	for name, c := range map[string]struct {
		extra, fields string
		want          error
	}{
		"fields with no version":        {"", base, measurementlist.ErrMalformed},
		"an unknown version":            {`"list_version":3,`, base, measurementlist.ErrUnknownVersion},
		"no svn":                        {`"list_version":2,`, `,"environment":"production","smt":true`, nil},
		"development environment typo":  {`"list_version":2,`, `,"environment":"staging","svn":6,"smt":true`, nil},
		"an unknown field":              {`"list_version":2,`, base + `,"extra":1`, measurementlist.ErrMalformed},
		"a retirement that cannot read": {`"list_version":2,`, base + `,"retired":{"kind":"Update"}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			p := onekey(t)
			p.foundRegistry()
			p.issue(listSpec{sequence: 3, expires: t0.Add(60 * 24 * time.Hour), extra: c.extra, images: v2Images(c.fields)})
			res, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{}, now)
			if err == nil {
				// an unreadable retirement revokes only that entry; the others are unaffected
				if r := res.List.Images["organisation"][0].Retired; name == "a retirement that cannot read" && r != nil && r.Kind == measurementlist.Revoked {
					return
				}
				t.Fatalf("accepted: %+v", res.List)
			}
			if c.want != nil && !strings.Contains(err.Error(), c.want.Error()) {
				t.Fatalf("refused with %v, want %v", err, c.want)
			}
		})
	}
}
