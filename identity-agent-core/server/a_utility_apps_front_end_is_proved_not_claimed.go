package server

import (
	"net/http"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// refuseFrontEnd decides which front end a sign-in to this asset is for, and
// whether it may start. It returns the kind to name in the signed challenge
// ("" for an asset that is not asked, or a sign-in that names none for an app
// made before apps could declare) or the status and words of a refusal.
//
// The kind is what the caller says, and a public page can say anything, so a
// kind is believed only as far as the request backs it (ADR-072 section 3):
//
//   - installed_app is accepted only when the core has verified a hardware
//     attestation of the installed app's own key (installedAppKey, set by
//     startFrontEndKeySignIn after verifyInstalledAppKey). Naming the kind is
//     no proof: otherwise a page that calls itself the installed app gets
//     round a switched-off browser.
//   - a request from a web page (a browser Origin header) or for a browser's
//     key is a browser's, and is refused if it names any other kind.
//   - an app that has declared its front ends admits only a kind it offers and
//     its owner has not switched off. An app made before it could declare has
//     not: it is not asked for a kind, as before.
//
// Any other asset is not asked.
func refuseFrontEnd(a asset.Asset, kind, browserKey string, fromAPage, installedAppKey bool) (string, int, string) {
	if a.AssetType != "app" {
		return "", 0, ""
	}
	if kind != "" && kind != asset.FrontEndBrowser && kind != asset.FrontEndInstalledApp {
		return "", http.StatusForbidden, "this sign-in does not say which front end it is for, 'browser' or 'installed_app'"
	}
	// installedAppKey is the caller's PROOF, never its claim: it is true only
	// where the core has itself verified a hardware attestation of the key
	// (startFrontEndKeySignIn), and never for a request from a page.
	anInstalledApp := installedAppKey && kind == asset.FrontEndInstalledApp && !fromAPage
	if (browserKey != "" || fromAPage) && kind != "" && kind != asset.FrontEndBrowser && !anInstalledApp {
		return "", http.StatusForbidden, "a sign-in asked for from a web page, or for a browser's key, is a browser front end's"
	}
	if browserKey != "" && !anInstalledApp {
		kind = asset.FrontEndBrowser
	}
	if kind == asset.FrontEndInstalledApp && !anInstalledApp {
		return "", http.StatusForbidden, "an installed-app sign-in needs the key of the utility app's installed front end proved in its device's hardware, and this request has none"
	}
	if why := a.FrontEndRefusal(kind); why != "" {
		return "", http.StatusForbidden, why
	}
	return kind, 0, ""
}

// frontEndRefusalNow is why the sign-in a challenge started may no longer
// finish, from the owner's setting as it stands now, or "". A site that is
// gone, or is not an app, is not asked here.
func (s *CoreServer) frontEndRefusalNow(b login.ChallengeBundle) string {
	if s.assetHandler == nil || b.SiteAID == "" {
		return ""
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return "the owner's front-end setting could not be read"
	}
	for _, a := range assets {
		if a.PairwiseAID == b.SiteAID {
			return a.FrontEndRefusal(b.FrontEnd)
		}
	}
	return ""
}
