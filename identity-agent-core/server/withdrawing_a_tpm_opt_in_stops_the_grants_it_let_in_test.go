package server

import (
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/secureenclave"
)

// The owner's TPM declarations are asked on every use of a grant, as the front-end switch
// is: a grant held by a TPM key stops speaking once the owner no longer accepts the kind
// of chip it was proved in, however long ago it was approved.

func (w *virtualWorld) grantSpeaks(t *testing.T) bool {
	t.Helper()
	person, ok := w.org.browserKeys().Whose("the-website", w.key, time.Now())
	if !ok {
		t.Fatal("no grant is held for the key")
	}
	return w.org.appKeyStillSpeaks("the-website", w.key, person)
}

func (w *virtualWorld) ownerSays(t *testing.T, set func(*asset.InstalledAppIdentity)) {
	t.Helper()
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	set(&a.InstalledApp)
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
}

func TestWithdrawingTPMKeysStopsAPhysicalChipsGrant(t *testing.T) {
	w := aVirtualTPMWorld(t, secureenclave.TPMClassPhysical, func(i *asset.InstalledAppIdentity) { i.TPMKeys = true })
	w.signedIn(t)
	if !w.grantSpeaks(t) {
		t.Fatal("the grant does not speak before the owner withdraws tpm_keys")
	}
	w.ownerSays(t, func(i *asset.InstalledAppIdentity) { i.TPMKeys = false })
	if w.grantSpeaks(t) {
		t.Fatal("a TPM key's grant kept speaking after the owner stopped accepting TPM keys")
	}
}

func TestWithdrawingVirtualTPMKeysStopsAVirtualTPMsGrantAndNotAChipsOne(t *testing.T) {
	both := func(i *asset.InstalledAppIdentity) { i.TPMKeys, i.VirtualTPMKeys = true, true }
	virtual := aVirtualTPMWorld(t, secureenclave.TPMClassVirtual, both)
	virtual.signedIn(t)
	if !virtual.grantSpeaks(t) {
		t.Fatal("the virtual TPM's grant does not speak before the owner withdraws virtual_tpm_keys")
	}
	virtual.ownerSays(t, func(i *asset.InstalledAppIdentity) { i.VirtualTPMKeys = false })
	if virtual.grantSpeaks(t) {
		t.Fatal("a virtual TPM's grant kept speaking after the owner stopped accepting virtual TPMs")
	}

	physical := aVirtualTPMWorld(t, secureenclave.TPMClassPhysical, both)
	physical.signedIn(t)
	physical.ownerSays(t, func(i *asset.InstalledAppIdentity) { i.VirtualTPMKeys = false })
	if !physical.grantSpeaks(t) {
		t.Fatal("a physical chip's grant stopped when only virtual TPMs were withdrawn")
	}
}

func TestATPMProofOfNoKnownClassSpeaksForNoOne(t *testing.T) {
	id := asset.InstalledAppIdentity{TPMKeys: true, VirtualTPMKeys: true}
	if tpmProofStillAllowed(&installedAppFact{Platform: "tpm"}, id) {
		t.Fatal("a TPM proof with no class was taken as allowed")
	}
	if !tpmProofStillAllowed(&installedAppFact{Platform: "android"}, asset.InstalledAppIdentity{}) {
		t.Fatal("the TPM rule stopped a key proved on another platform")
	}
}
