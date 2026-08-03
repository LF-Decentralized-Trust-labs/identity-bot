package secureenclave

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// A synthetic report with known bytes at every field we read. Offsets are the
// thing most likely to be silently wrong — a bad one yields plausible garbage
// rather than an error — so each field gets a distinct filler and the tests
// assert we read back exactly what was written there.
func buildReport(mutate func(r []byte)) []byte {
	r := make([]byte, ReportSize)

	binary.LittleEndian.PutUint64(r[offPolicy:], 0x30000)       // no DEBUG bit
	binary.LittleEndian.PutUint64(r[offPlatformInfo:], 0x21)    // SMT + AliasCheckComplete-ish
	binary.LittleEndian.PutUint32(r[offSignerInfo:], 0)         // VCEK-signed
	binary.LittleEndian.PutUint64(r[offReportedTCB:], 0xDEADBE) //

	for i := 0; i < ReportDataSize; i++ {
		r[offReportData+i] = 0xAA
	}
	for i := 0; i < MeasurementSize; i++ {
		r[offMeasurement+i] = 0xBB
	}
	for i := 0; i < 32; i++ {
		r[offHostData+i] = 0xCC
	}
	for i := 0; i < ChipIDSize; i++ {
		r[offChipID+i] = 0xDD
	}
	for i := offSignature; i < ReportSize; i++ {
		r[i] = 0xEE
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

func TestEveryFieldIsReadFromWhereItActuallyLives(t *testing.T) {
	p, err := ParseSNPReport(buildReport(nil))
	if err != nil {
		t.Fatalf("parsing a well-formed report: %v", err)
	}
	checks := []struct {
		name, got, want string
	}{
		{"chip id", p.ChipIDHex(), hex.EncodeToString(rep(0xDD, ChipIDSize))},
		{"measurement", p.MeasurementHex(), hex.EncodeToString(rep(0xBB, MeasurementSize))},
		{"report data", hex.EncodeToString(p.ReportData), hex.EncodeToString(rep(0xAA, ReportDataSize))},
		{"host data", hex.EncodeToString(p.HostData), hex.EncodeToString(rep(0xCC, 32))},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s read from the wrong offset:\n got %s\nwant %s", c.name, c.got, c.want)
		}
	}
	if p.Policy != 0x30000 {
		t.Errorf("policy = %#x, want %#x", p.Policy, 0x30000)
	}
	if p.ReportedTCB != 0xDEADBE {
		t.Errorf("reported tcb = %#x", p.ReportedTCB)
	}
	if p.DebugAllowed() {
		t.Error("reported DEBUG allowed on a policy that does not set the bit")
	}
	if p.Unsigned() {
		t.Error("reported unsigned on a VCEK-signed report")
	}
}

// The DEBUG bit is the one that matters most and is easiest to miss: a report
// with it set passes every signature and certificate check, and the host can
// read guest memory anyway.
func TestDebugPolicyIsSurfaced(t *testing.T) {
	r := buildReport(func(r []byte) {
		binary.LittleEndian.PutUint64(r[offPolicy:], 0x30000|policyDebugBit)
	})
	p, err := ParseSNPReport(r)
	if err != nil {
		t.Fatalf("a DEBUG report must still parse — refusing it is the caller's policy: %v", err)
	}
	if !p.DebugAllowed() {
		t.Fatal("POLICY bit 19 was set and DebugAllowed() did not say so")
	}
}

func TestReportsThatCannotMeanAnythingAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		report []byte
		want   string
	}{
		{
			// A caller that ignores the firmware's STATUS field and copies the
			// response buffer anyway produces exactly this.
			name:   "an all-zero report",
			report: make([]byte, ReportSize),
			want:   "entirely zero",
		},
		{
			// The host can mask the chip identifier. A zeroed one cannot pin an
			// allowlist to a machine.
			name: "a masked chip id",
			report: buildReport(func(r []byte) {
				for i := 0; i < ChipIDSize; i++ {
					r[offChipID+i] = 0
				}
			}),
			want: "all-zero CHIP_ID",
		},
		{
			name: "a report that declares itself unsigned",
			report: buildReport(func(r []byte) {
				binary.LittleEndian.PutUint32(r[offSignerInfo:], signerNone<<2)
			}),
			want: "unsigned",
		},
		{
			name: "a report with no signature",
			report: buildReport(func(r []byte) {
				for i := offSignature; i < ReportSize; i++ {
					r[i] = 0
				}
			}),
			want: "no signature",
		},
		{
			name:   "the wrong length",
			report: make([]byte, 512),
			want:   "512 bytes",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSNPReport(c.report)
			if err == nil {
				t.Fatal("accepted a report that cannot identify anything")
			}
			if !contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q, so an operator cannot act on it",
					err.Error(), c.want)
			}
		})
	}
}

// Parsing is not verification, and a machine identity read from an unverified
// report is still only a claim. What must hold is that the value is carried
// through unchanged — an identity that silently differs from the report it came
// from would compare unequal at enrolment and read as "different machine".
func TestMachineIdentityCarriesTheChipIDThrough(t *testing.T) {
	raw := buildReport(nil)
	id, err := MachineIdentityFromSNPReport(raw)
	if err != nil {
		t.Fatalf("deriving an identity: %v", err)
	}
	if !id.Known() {
		t.Fatal("a parsed report yielded an unknown machine")
	}
	if id.Kind != MachineIDSNPChip {
		t.Errorf("kind = %q, want %q", id.Kind, MachineIDSNPChip)
	}
	if id.Value != hex.EncodeToString(rep(0xDD, ChipIDSize)) {
		t.Errorf("chip id did not survive: %s", id.Value)
	}

	// Round-tripping through the recorded form must preserve identity, or an
	// enrolled machine stops matching itself after a restart.
	back, err := ParseMachineIdentity(string(id.Kind), id.Value)
	if err != nil {
		t.Fatalf("reading back a recorded identity: %v", err)
	}
	if !back.Matches(id) {
		t.Error("a recorded identity did not match the one it was recorded from")
	}
}

func TestDifferentKindsNeverMatch(t *testing.T) {
	// Same bytes, different hardware namespace. These are not the same machine
	// and must never compare equal, however unlikely the collision.
	snp := MachineIdentity{Kind: MachineIDSNPChip, Value: "abcd"}
	tpm := MachineIdentity{Kind: MachineIDTPMEndorsement, Value: "abcd"}
	if snp.Matches(tpm) {
		t.Error("an SNP chip id matched a TPM endorsement hash")
	}
	// And an unknown identity matches nothing, including another unknown —
	// otherwise two unidentified machines would be treated as the same one.
	var a, b MachineIdentity
	if a.Matches(b) {
		t.Error("two unidentified machines compared equal")
	}
	if a.Matches(snp) || snp.Matches(a) {
		t.Error("an unidentified machine matched an identified one")
	}
}

func TestAnUnidentifiedMachineSaysWhy(t *testing.T) {
	// On a host with neither an SNP guest device nor a usable TPM, the answer
	// must be actionable rather than a bare false.
	id := IdentifyMachine()
	if id.Known() {
		t.Skipf("this host has hardware identity %s — nothing to assert", id)
	}
	if id.Why == "" {
		t.Error("no machine identity and no reason given")
	}
	if id.Value != "" {
		t.Errorf("an unidentified machine carries a value: %q", id.Value)
	}
}

func rep(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func contains(hay, needle string) bool {
	return len(needle) == 0 || (len(hay) >= len(needle) && indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
