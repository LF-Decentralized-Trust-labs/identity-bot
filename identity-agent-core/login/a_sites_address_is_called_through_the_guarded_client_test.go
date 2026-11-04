package login

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

type recordingTransport struct {
	name  string
	calls *[]string
}

func (r recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.calls = append(*r.calls, r.name+" "+req.URL.Path)
	return nil, errors.New("not answered")
}

// Every call to an address a site chose goes through Handler.PeerClient, which
// the server sets to the guarded client, and none through the plain HTTPClient.
func TestEveryCallToASitesAddressUsesThePeerClient(t *testing.T) {
	var calls []string
	h := &Handler{
		DevRelay:   "http://relay.invalid",
		HTTPClient: &http.Client{Transport: recordingTransport{"plain", &calls}},
		PeerClient: func(string) *http.Client {
			return &http.Client{Transport: recordingTransport{"guarded", &calls}}
		},
		dataDir: t.TempDir(),
	}
	const site = "http://site.invalid"
	_, _ = h.fetchChallengeBundle(site, "tok")
	_ = h.postAssertion(site+"/callback", "tok", &Assertion{})
	_ = h.registerPairwiseOnDevRelay(&SiteRelationship{RelayOOBI: site + "/oobi/EPW"}, &ChallengeBundle{SiteOOBI: site + "/oobi/ESITE"})
	_, _ = h.resolveSiteKey(site+"/oobi/ESITE", "ESITE")

	if len(calls) < 3 {
		t.Fatalf("expected the site's calls to be made, saw %v", calls)
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "guarded ") {
			t.Errorf("a call to the site's address did not use the guarded client: %q", c)
		}
	}
}

// The introduction of the organisation that delegated a site is another address
// the site chose, and is read through the same client.
func TestTheDelegatorsIntroductionIsReadThroughThePeerClient(t *testing.T) {
	site, delegator := aDelegatedSite(t, true)
	siteSrv, delSrv := site.serve(t), delegator.serve(t)
	var calls []string
	h := &Handler{
		HTTPClient: &http.Client{Transport: recordingTransport{"plain", &calls}},
		PeerClient: func(string) *http.Client {
			return &http.Client{Transport: countingTransport{"guarded", &calls}}
		},
	}
	id, err := IdentityFromOOBI(h.peerClient(siteSrv.URL), siteSrv.URL+"/oobi/"+site.aid, site.aid)
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := h.verifyDelegationAnchor(anchoredBundle(site.aid, delegator.aid, delSrv.URL+"/oobi/"+delegator.aid), id); err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 {
		t.Fatal("the delegator's introduction was not read at all")
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "guarded ") {
			t.Errorf("the delegator's introduction was read with %q", c)
		}
	}
}

type countingTransport struct {
	name  string
	calls *[]string
}

func (r countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.calls = append(*r.calls, r.name+" "+req.URL.Path)
	return http.DefaultTransport.RoundTrip(req)
}
