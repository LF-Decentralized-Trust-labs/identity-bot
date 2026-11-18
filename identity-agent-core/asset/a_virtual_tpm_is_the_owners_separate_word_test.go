package asset

import (
	"strings"
	"testing"
)

func TestVirtualTPMKeysIsAcceptedOnlyOnTopOfTPMKeys(t *testing.T) {
	offered := []string{FrontEndInstalledApp}
	for _, tc := range []struct {
		name    string
		id      InstalledAppIdentity
		wantErr bool
	}{
		{"physical only", InstalledAppIdentity{TPMKeys: true}, false},
		{"both", InstalledAppIdentity{TPMKeys: true, VirtualTPMKeys: true}, false},
		{"virtual alone", InstalledAppIdentity{VirtualTPMKeys: true}, true},
		{"virtual with a phone program but no tpm_keys", InstalledAppIdentity{VirtualTPMKeys: true, AppleAppID: "TEAM123456.org.example.portal"}, true},
	} {
		err := CheckInstalledAppIdentity("app", offered, tc.id)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "virtual_tpm_keys") {
			t.Errorf("%s: the refusal does not name the declaration: %v", tc.name, err)
		}
	}
}

// virtual_tpm_keys alone names something, so an identity that holds only it is not "empty"
// and is checked (and refused) rather than passed over.
func TestAnIdentityThatNamesOnlyTheVirtualWordIsNotEmpty(t *testing.T) {
	if (InstalledAppIdentity{VirtualTPMKeys: true}).IsEmpty() {
		t.Fatal("virtual_tpm_keys alone counted as naming nothing")
	}
	if err := CheckInstalledAppIdentity("app", nil, InstalledAppIdentity{TPMKeys: true, VirtualTPMKeys: true}); err == nil {
		t.Fatal("an app with no installed front end named a virtual TPM")
	}
}

func TestAVirtualTPMIsAcceptedOnlyWhenBothWordsAreSaid(t *testing.T) {
	for _, tc := range []struct {
		id   InstalledAppIdentity
		want bool
	}{
		{InstalledAppIdentity{}, false},
		{InstalledAppIdentity{TPMKeys: true}, false},
		{InstalledAppIdentity{VirtualTPMKeys: true}, false},
		{InstalledAppIdentity{TPMKeys: true, VirtualTPMKeys: true}, true},
	} {
		if got := tc.id.AcceptsVirtualTPM(); got != tc.want {
			t.Errorf("%+v: %v", tc.id, got)
		}
	}
}
