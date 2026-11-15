package main

import "testing"

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		maker, cn string
		root      bool
		want      string
	}{
		{"Infineon", "IFX-KeyId-1", false, classPhysical},
		{"AMD", "Microsoft Pluton Root CA 2021", true, classPhysical},
		{"Microsoft", "Microsoft TPM Root Certificate Authority 2014", true, classPhysical},
		{"Microsoft", "WUS-IFX-KEYID-DA20", false, classPhysical},
		{"Microsoft", "NCU-ntc-keyid-e151", false, classPhysical},
		{"Microsoft", "MSFT-KEYID-1565", false, classVirtual},
		{"Microsoft", "EUS-msft-keyid-1565", false, classVirtual},
		{"Microsoft", "MSFT-KEYID-1565-V2", false, classVirtual},
		{"Microsoft", "WUS-WEC-NAMEID-19BC", false, classUnclassified}, // a vendor id not known: not trusted
		{"Microsoft", "SEA-IFX-KEYID-1", false, classPhysical},         // a region not seen yet still reads its vendor id
		{"Microsoft", "SEA-MSFT-KEYID-1", false, classVirtual},
		{"Microsoft", "MSFT-IFX-KEYID-1", false, classUnclassified}, // two vendor ids: not a name Microsoft uses
		{"Microsoft", "Something Else CA", false, classUnclassified},
		{"Microsoft", "", false, classUnclassified},
	} {
		if got := classify(c.maker, c.cn, c.root); got != c.want {
			t.Errorf("classify(%s, %q) = %s, want %s", c.maker, c.cn, got, c.want)
		}
	}
}
