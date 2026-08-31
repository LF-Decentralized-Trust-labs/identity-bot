package server

import (
	"strings"
	"testing"

	"identity-agent-core/secureenclave"
)

// Every refusal a real detector can produce must say something the person can
// act on, must not blame their machine for our gaps, and must not throw away
// the remedy the detector already worked out.
func TestEveryRefusalSaysSomethingTrueAndUseful(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cap        secureenclave.Capability
		mustSay    []string
		mustNotSay []string
	}{
		{
			name:       "android app never reported",
			cap:        secureenclave.Unproven("app_did_not_report_key_protection", "the Android Keystore can only be probed from the app"),
			mustSay:    []string{"gap in the app"},
			mustNotSay: []string{"this machine was checked", "report it"},
		},
		{
			name:    "windows tpm present but unprovisioned",
			cap:     secureenclave.Capability{Status: secureenclave.Present, Kind: secureenclave.KindTPM2, Reason: "key_finalize_refused", Detail: "the TPM may be unprovisioned, in lockout, or out of storage"},
			mustSay: []string{"unprovisioned"},
		},
		{
			name:    "darwin no enclave",
			cap:     secureenclave.Capability{Status: secureenclave.Absent, Reason: "no_secure_enclave_on_this_hardware", Detail: "the Secure Enclave token is unimplemented on this machine"},
			mustSay: []string{"unimplemented on this machine"},
		},
		{
			name:       "a platform with no detector",
			cap:        secureenclave.NotImplemented("plan9"),
			mustSay:    []string{"has not been written", "gap in this software"},
			mustNotSay: []string{"this machine was checked"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := refusalFor(tc.cap)
			for _, want := range tc.mustSay {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q\ngot: %s", want, got)
				}
			}
			for _, never := range tc.mustNotSay {
				if strings.Contains(got, never) {
					t.Errorf("must not say %q\ngot: %s", never, got)
				}
			}
		})
	}
}
