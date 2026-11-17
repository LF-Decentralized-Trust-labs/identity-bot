package server

import (
	"net/http/httptest"
	"testing"

	"identity-agent-core/keriengine"
)

// After a restart the engine holds only the owner's identity. Starting hands it
// back every asset's, of either kind, so the log the cross-check serves for an
// asset is there without an OOBI request having come first.
func TestEveryAssetIdentityIsRevivedAtStart(t *testing.T) {
	s, appAID, _ := provisionedApp(t)
	agent, err := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/public/kel-check", nil)
	// The agent is delegated and not waiting for a device: nothing in this
	// world moves the key elsewhere.
	if agent.ApprovalPending {
		t.Fatal("the agent is waiting for an approval, so this tests nothing for it")
	}
	for _, aid := range []string{appAID, agent.PairwiseAID} {
		if _, ok := s.servedLog(aid, r); !ok {
			t.Fatalf("%s is not served before the restart", aid)
		}
	}

	s.KeriDriver = keriengine.New()
	s.engineSigns()
	s.reloadKeyLogs()
	for _, aid := range []string{appAID, agent.PairwiseAID} {
		if _, ok := s.servedLog(aid, r); ok {
			t.Fatalf("%s is still served after a restart, so this tests nothing", aid)
		}
	}

	s.reviveAssetIdentities()
	for _, aid := range []string{appAID, agent.PairwiseAID} {
		if log, ok := s.servedLog(aid, r); !ok || len(log) == 0 {
			t.Fatalf("%s is not served after start-up revived it", aid)
		}
	}
	// A second start finds them held and leaves them be.
	s.reviveAssetIdentities()
	if _, ok := s.servedLog(appAID, r); !ok {
		t.Fatal("reviving twice lost an identity")
	}
}
