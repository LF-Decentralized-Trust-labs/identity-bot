package login

import "fmt"

// The kinds of front end a sign-in to a utility app can name (ADR-072 section 3).
const (
	FrontEndBrowser      = "browser"
	FrontEndInstalledApp = "installed_app"
)

// CheckFrontEnd refuses a front-end kind that is not one of the two, and
// accepts "" (a challenge that names none). The person's agent runs it on the
// signed challenge before showing consent, and a verifier runs it on the kind
// it expects.
func CheckFrontEnd(kind string) error {
	switch kind {
	case "", FrontEndBrowser, FrontEndInstalledApp:
		return nil
	}
	return fmt.Errorf("a sign-in names a front end that is not 'browser' or 'installed_app'")
}
