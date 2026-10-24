package server

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
)

// An AI agent whose key this Identity Agent derived publishes its log with its
// own signature over each event, so the log verifies to somebody holding only
// what was served.
func TestAnAgentsPublishedLogCarriesItsOwnSignature(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	const index = 7
	pub, nextPub, err := asset.DeriveAssetKeypair(s.DataDir, index)
	if err != nil {
		t.Fatal(err)
	}
	e := keriengine.New()
	rootPub, rootNext, _ := asset.DeriveAssetKeypair(s.DataDir, 99)
	rootSeed, _ := asset.AssetSigningSeed(s.DataDir, 99)
	signsWithSeeds(e, rootSeed)
	if _, err := e.CreateInceptionNamed(iacrypto.VerkeyQB64(rootPub), iacrypto.VerkeyQB64(rootNext), "owner"); err != nil {
		t.Fatal(err)
	}
	dip, err := e.CreateDelegatedInception(iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub), "Research assistant", "owner")
	if err != nil {
		t.Fatal(err)
	}
	a := asset.Asset{PairwiseAID: dip.AID, SigningIndex: index, DisplayName: "Research assistant"}

	rawEvents, sigs := s.assetEventsAndSignatures(a, []string{dip.RawBytesB64})
	if sigs[0] == "" {
		t.Fatal("the agent's inception is served unsigned")
	}
	raw, _ := base64.StdEncoding.DecodeString(rawEvents[0])
	got, err := drivers.ValidateKELFromBytes(drivers.ValidateKELInput{
		AID: dip.AID, RawEvents: [][]byte{raw}, CesrSignatures: sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified || got.EventsUnsigned != 0 {
		t.Fatalf("the served log did not verify against the agent's own key: %+v", got)
	}

	// A machine-enrolled asset's key is on its own machine: nothing is invented.
	_, none := s.assetEventsAndSignatures(asset.Asset{PairwiseAID: dip.AID}, []string{dip.RawBytesB64})
	if none[0] != "" {
		t.Fatal("a signature was produced for an asset whose key this agent does not hold")
	}
}
