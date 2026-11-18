package login

import (
	"net/http"
	"testing"
	"time"
)

// SiteIsDelegatedBy is how a person's Identity Agent knows an identifier an organisation names as
// one of its sites is one, before it says anything about the person's identifier there.
func TestASiteIsTheOrganisationsOnlyWhenItIsTheOrganisationOrWasDelegatedByIt(t *testing.T) {
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}

	t.Run("the organisation's own identifier is its own", func(t *testing.T) {
		if err := h.SiteIsDelegatedBy("EORG", "", "EORG", ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a site the organisation approved", func(t *testing.T) {
		site, delegator := aDelegatedSite(t, true)
		siteSrv, delSrv := site.serve(t), delegator.serve(t)
		if err := h.SiteIsDelegatedBy(site.aid, siteSrv.URL+"/oobi/"+site.aid, delegator.aid, delSrv.URL+"/oobi/"+delegator.aid); err != nil {
			t.Fatalf("a delegation the organisation approved was refused: %v", err)
		}
	})
	t.Run("a site that only claims the organisation", func(t *testing.T) {
		site, delegator := aDelegatedSite(t, false)
		siteSrv, delSrv := site.serve(t), delegator.serve(t)
		if err := h.SiteIsDelegatedBy(site.aid, siteSrv.URL+"/oobi/"+site.aid, delegator.aid, delSrv.URL+"/oobi/"+delegator.aid); err == nil {
			t.Fatal("a site the organisation never approved was taken for its own")
		}
	})
	t.Run("a site that is another organisation's", func(t *testing.T) {
		site, _ := aDelegatedSite(t, true)
		_, other := aDelegatedSite(t, true)
		siteSrv, otherSrv := site.serve(t), other.serve(t)
		if err := h.SiteIsDelegatedBy(site.aid, siteSrv.URL+"/oobi/"+site.aid, other.aid, otherSrv.URL+"/oobi/"+other.aid); err == nil {
			t.Fatal("one organisation's site was taken for another's")
		}
	})
	t.Run("a site that serves no log, and an empty request", func(t *testing.T) {
		if err := h.SiteIsDelegatedBy("ESITE", "http://127.0.0.1:1/oobi/ESITE", "EORG", ""); err == nil {
			t.Fatal("a site that could not be read was taken for the organisation's")
		}
		if err := h.SiteIsDelegatedBy("", "", "EORG", ""); err == nil {
			t.Fatal("no site was taken for one")
		}
	})
}
