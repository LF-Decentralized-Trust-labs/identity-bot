package login

import (
	"identity-agent-core/drivers"
)

// SignChallengeForAsset signs the canonical challenge body using the asset's KERI key
// (looked up by display name in the driver) and attaches the signature to the bundle.
func SignChallengeForAsset(bundle ChallengeBundle, assetName string, driver interface {
	SignForName(string, string) (*drivers.DriverSignForNameResponse, error)
}) error {
	body := canonicalChallengeBody(bundle)
	resp, err := driver.SignForName(assetName, body)
	if err != nil {
		return err
	}
	bundle.Sig = resp.Sig
	return nil
}
