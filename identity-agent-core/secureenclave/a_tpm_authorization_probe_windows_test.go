//go:build windows && tpmprobe

package secureenclave

// THE WINDOWS TPM AUTHORIZATION PROBE (ADR-074 section 3).
//
// The controller key of a Windows computer is a TPM key whose authorization value
// is HKDF(GK, "tpm-auth"). Nothing here has ever run on a TPM. This probe runs the
// shipped functions (createMachineKey, setUsageAuth, supplyUsageAuth, and the
// tpmSigner) against the real Microsoft Platform Crypto Provider and says, one line
// each, whether the design's five claims hold:
//
//	CREATE   a key is created with the value, the property being accepted before it is finalised
//	SIGN     signing with the right value succeeds from a process with no prompt
//	WRONG    the wrong value is refused
//	NONE     no value is refused
//	LOCKOUT  the TPM's lockout counter rises on a refusal
//
// and, beyond the five, CORE: the tpmSigner itself makes, records, reopens and
// signs with its key, refuses a key it did not make, and refuses when locked.
//
// HOW TO RUN: scripts/tpm-authorization-probe.ps1 (from a Windows PowerShell,
// in the identity-bot checkout, on a machine with a TPM 2.0). It compiles this
// file with `go test -c -tags tpmprobe`, runs it in your session, then again as a
// scheduled task with no desktop (which is what the core is), and prints the
// verdict.
//
// COST: the probe sends ONE wrong value and ONE missing value to a key of its own.
// A TPM counts failed authorizations toward a lockout it shares with everything
// else on the machine, Windows Hello included. The probe reads the counter first
// and stops without trying if fewer than 3 failures remain. It deletes its keys.
//
// Phases, by PROBE_PHASE (the script sets them; "all" is the default):
//
//	all      create, sign, refuse, core, cleanup, in one process
//	create   make the probe key, write PROBE_STATE (a throwaway value, in a file)
//	sign     sign with the right value from PROBE_STATE (the non-interactive check)
//	refuse   try the wrong value and no value, and read the lockout counter
//	core     the tpmSigner end to end
//	cleanup  delete the probe key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type aProbeState struct {
	Name string `json:"name"`
	Auth string `json:"auth"` // hex of the probe's own throwaway value
	Pub  string `json:"pub"`  // hex of the key's public point
}

var theProbeVerdicts []string

func verdict(t *testing.T, name string, ok bool, detail string) {
	t.Helper()
	word := "PASS"
	if !ok {
		word = "FAIL"
		t.Fail()
	}
	line := fmt.Sprintf("PROBE %-8s %s  %s", name, word, detail)
	theProbeVerdicts = append(theProbeVerdicts, line)
	fmt.Println(line)
}

func info(format string, a ...any) { fmt.Printf("PROBE info     "+format+"\n", a...) }

func TestTPMAuthorizationProbe(t *testing.T) {
	phase := os.Getenv("PROBE_PHASE")
	if phase == "" {
		phase = "all"
	}
	statePath := os.Getenv("PROBE_STATE")
	if statePath == "" {
		statePath = os.TempDir() + `\identity-agent-tpm-probe.json`
	}
	if !HardwareRootStatus().RootKeyPermitted() {
		t.Skipf("no usable TPM here: %s", HardwareRootStatus().String())
	}
	info("phase %s, interactive=%v", phase, theProcessHasADesktop())

	switch phase {
	case "all":
		st := probeCreate(t, statePath)
		probeSign(t, st, "in this process")
		probeRefuse(t, st)
		probeCore(t)
		probeCleanup(t, st, statePath)
	case "create":
		probeCreate(t, statePath)
	case "sign":
		probeSign(t, readProbeState(t, statePath), "from a process with no desktop")
	case "refuse":
		probeRefuse(t, readProbeState(t, statePath))
	case "core":
		probeCore(t)
	case "cleanup":
		probeCleanup(t, readProbeState(t, statePath), statePath)
	default:
		t.Fatalf("unknown PROBE_PHASE %q", phase)
	}
}

// theProcessHasADesktop is a guess for the log only: SESSIONNAME is set in a
// logged-on session (Console, RDP-Tcp#n) and not in a scheduled task that runs
// whether or not anyone is logged on.
func theProcessHasADesktop() bool { return os.Getenv("SESSIONNAME") != "" }

func readProbeState(t *testing.T, path string) aProbeState {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no probe key yet (run the create phase first): %v", err)
	}
	var st aProbeState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// ---- the TPM's own counter, read through TBS --------------------------------

var (
	procTbsiCreate     = tbs.NewProc("Tbsi_Context_Create")
	procTbsipSubmit    = tbs.NewProc("Tbsip_Submit_Command")
	procTbsipCloseCtx  = tbs.NewProc("Tbsip_Context_Close")
	theLockoutCounter  = uint32(0x20E) // TPM_PT_LOCKOUT_COUNTER
	theLockoutMaxFails = uint32(0x20F) // TPM_PT_MAX_AUTH_FAIL
)

// theTPMProperty reads one TPM_PT_* value with TPM2_GetCapability, a command a
// standard user may send. ok is false when the TPM cannot be asked.
func theTPMProperty(prop uint32) (value uint32, ok bool) {
	params := struct{ version, flags uint32 }{2, 4} // TBS_CONTEXT_VERSION_TWO, includeTpm20
	var ctx uintptr
	if r, _, _ := procTbsiCreate.Call(uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&ctx))); r != 0 {
		return 0, false
	}
	defer procTbsipCloseCtx.Call(ctx)
	cmd := []byte{
		0x80, 0x01, // TPM_ST_NO_SESSIONS
		0, 0, 0, 22, // size
		0, 0, 0x01, 0x7A, // TPM_CC_GetCapability
		0, 0, 0, 0x06, // TPM_CAP_TPM_PROPERTIES
		byte(prop >> 24), byte(prop >> 16), byte(prop >> 8), byte(prop),
		0, 0, 0, 1, // one property
	}
	out := make([]byte, 256)
	n := uint32(len(out))
	if r, _, _ := procTbsipSubmit.Call(ctx, 0, 200, uintptr(unsafe.Pointer(&cmd[0])), uintptr(len(cmd)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&n))); r != 0 || n < 27 {
		return 0, false
	}
	if rc := uint32(out[6])<<24 | uint32(out[7])<<16 | uint32(out[8])<<8 | uint32(out[9]); rc != 0 {
		return 0, false
	}
	// header(10) moreData(1) capability(4) count(4) property(4) value(4)
	if got := uint32(out[19])<<24 | uint32(out[20])<<16 | uint32(out[21])<<8 | uint32(out[22]); got != prop {
		return 0, false
	}
	return uint32(out[23])<<24 | uint32(out[24])<<16 | uint32(out[25])<<8 | uint32(out[26]), true
}

// ---- helpers over the provider ------------------------------------------------

func openTheKey(t *testing.T, provider windows.Handle, name string) (windows.Handle, uint32) {
	t.Helper()
	n, _ := windows.UTF16PtrFromString(name)
	var key windows.Handle
	r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(n)), 0, ncryptSilentFlag)
	return key, uint32(r)
}

// signWith opens the key, supplies auth (nil supplies nothing) and signs. The
// status is the provider's, so a refusal can be named.
func signWith(t *testing.T, name string, auth []byte, msg []byte) (sig []byte, status uint32, where string) {
	t.Helper()
	provider, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer procFreeObject.Call(uintptr(provider))
	key, st := openTheKey(t, provider, name)
	if st != 0 {
		return nil, st, "open"
	}
	defer procFreeObject.Call(uintptr(key))
	if auth != nil {
		wide := tpmUsageAuthWide(auth)
		p, _ := windows.UTF16PtrFromString(ncryptPinProperty)
		if r, _, _ := procSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(p)),
			uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)*2), ncryptSilentFlag); r != 0 {
			return nil, uint32(r), "set the value"
		}
	}
	sum := sha256.Sum256(msg)
	var need uint32
	if r, _, _ := procSignHash.Call(uintptr(key), 0, uintptr(unsafe.Pointer(&sum[0])), uintptr(len(sum)),
		0, 0, uintptr(unsafe.Pointer(&need)), ncryptSilentFlag); r != 0 {
		return nil, uint32(r), "size the signature"
	}
	sig = make([]byte, need)
	if r, _, _ := procSignHash.Call(uintptr(key), 0, uintptr(unsafe.Pointer(&sum[0])), uintptr(len(sum)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(need), uintptr(unsafe.Pointer(&need)), ncryptSilentFlag); r != 0 {
		return nil, uint32(r), "sign"
	}
	return sig[:need], 0, ""
}

func verifies(pub, msg, sig []byte) bool {
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	if x == nil || len(sig) != 64 {
		return false
	}
	sum := sha256.Sum256(msg)
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, sum[:],
		new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func deleteTheKey(name string) {
	provider, err := openProvider()
	if err != nil {
		return
	}
	defer procFreeObject.Call(uintptr(provider))
	n, _ := windows.UTF16PtrFromString(name)
	var key windows.Handle
	if r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(n)), 0, ncryptSilentFlag); r == 0 {
		procDeleteKey.Call(uintptr(key), ncryptSilentFlag) // frees the handle on success
	}
}

// ---- the phases ---------------------------------------------------------------

func probeCreate(t *testing.T, statePath string) aProbeState {
	t.Helper()
	var rnd [8]byte
	rand.Read(rnd[:])
	auth := make([]byte, tpmAuthLen)
	rand.Read(auth)
	st := aProbeState{Name: "IdentityAgentAuthProbe." + hex.EncodeToString(rnd[:]), Auth: hex.EncodeToString(auth)}

	provider, err := openProvider()
	if err != nil {
		t.Fatalf("the platform crypto provider would not open: %v", err)
	}
	defer procFreeObject.Call(uintptr(provider))
	name, _ := windows.UTF16PtrFromString(st.Name)
	key, err := createMachineKey(provider, name, auth) // the shipped path: the value is set before finalising
	if err != nil {
		verdict(t, "CREATE", false, "the TPM would not make a key with the value: "+err.Error()+
			"  (the property is not accepted before finalising, or at all: the design needs a decision, see ADR-074 section 3)")
		return st
	}
	defer procFreeObject.Call(uintptr(key))
	pub, err := exportPublic(key)
	if err != nil {
		verdict(t, "CREATE", false, err.Error())
		return st
	}
	st.Pub = hex.EncodeToString(pub)
	verdict(t, "CREATE", true, "key "+st.Name+" created with an authorization value, "+ncryptPinProperty+" accepted before finalising")
	b, _ := json.Marshal(st)
	if err := os.WriteFile(statePath, b, 0o600); err != nil {
		t.Fatalf("cannot write the probe state: %v", err)
	}
	return st
}

func probeSign(t *testing.T, st aProbeState, where string) {
	t.Helper()
	auth, _ := hex.DecodeString(st.Auth)
	pub, _ := hex.DecodeString(st.Pub)
	msg := []byte("tpm authorization probe")
	sig, status, at := signWith(t, st.Name, auth, msg)
	switch {
	case status != 0:
		verdict(t, "SIGN", false, fmt.Sprintf("signing with the right value %s failed at %q (0x%X)", where, at, status))
	case !verifies(pub, msg, sig):
		verdict(t, "SIGN", false, "the signature did not verify against the key's public key")
	default:
		verdict(t, "SIGN", true, "signed with the right value "+where+", no prompt, and it verifies")
	}
}

func probeRefuse(t *testing.T, st aProbeState) {
	t.Helper()
	auth, _ := hex.DecodeString(st.Auth)
	wrong := append([]byte{}, auth...)
	wrong[0] ^= 0xff
	msg := []byte("tpm authorization probe")

	before, haveBefore := theTPMProperty(theLockoutCounter)
	max, haveMax := theTPMProperty(theLockoutMaxFails)
	if haveBefore && haveMax {
		info("TPM lockout counter %d of %d", before, max)
		if max-before < 3 {
			verdict(t, "WRONG", false, "NOT RUN: fewer than 3 failed authorizations remain before the TPM locks; wait for the counter to fall and run again")
			verdict(t, "NONE", false, "NOT RUN, as above")
			return
		}
	} else {
		info("the TPM lockout counter cannot be read from this process, so LOCKOUT will be reported as UNKNOWN")
	}

	_, status, at := signWith(t, st.Name, wrong, msg)
	verdict(t, "WRONG", status != 0, fmt.Sprintf("the wrong value: status 0x%X at %q (a nonzero status is a refusal)", status, at))
	mid, haveMid := theTPMProperty(theLockoutCounter)

	_, status, at = signWith(t, st.Name, nil, msg)
	verdict(t, "NONE", status != 0, fmt.Sprintf("no value: status 0x%X at %q (nonzero is a refusal, and it did not wait for a prompt)", status, at))
	after, haveAfter := theTPMProperty(theLockoutCounter)

	switch {
	case !haveBefore || !haveMid || !haveAfter:
		line := "PROBE LOCKOUT  UNKNOWN  the counter could not be read; read TPM_PT_LOCKOUT_COUNTER by hand (tpmtool or Get-Tpm) before and after a refusal"
		fmt.Println(line)
		theProbeVerdicts = append(theProbeVerdicts, line)
	default:
		verdict(t, "LOCKOUT", mid > before, fmt.Sprintf("the counter went %d -> %d after the wrong value, and %d after no value", before, mid, after))
	}

	// And the right value still works afterwards: a refusal did not break the key.
	if sig, status, at := signWith(t, st.Name, auth, msg); status != 0 {
		verdict(t, "SIGN2", false, fmt.Sprintf("after the refusals the right value failed at %q (0x%X)", at, status))
	} else {
		pub, _ := hex.DecodeString(st.Pub)
		verdict(t, "SIGN2", verifies(pub, msg, sig), "the right value still signs after the refusals")
	}
}

// probeCore runs the tpmSigner itself, for a profile whose gate is a test gate.
func probeCore(t *testing.T) {
	t.Helper()
	var rnd [6]byte
	rand.Read(rnd[:])
	profile := "probe-" + hex.EncodeToString(rnd[:])
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{profile, true})
	keyName := ProfileKeyName(machineKeyName, profile)
	defer deleteTheKey(keyName)

	mk := func() *tpmSigner { return newTPMSigner().(*tpmSigner).forProfileAt(dir).(*tpmSigner) }
	first := mk()
	if !first.Available() {
		verdict(t, "CORE", false, "the signer would not make its key: "+fmt.Sprint(first.whyUnavailable()))
		return
	}
	pub, err := first.PublicKey()
	if err != nil {
		verdict(t, "CORE", false, err.Error())
		return
	}
	msg := []byte("core path")
	sig, err := first.Sign(msg)
	ok := err == nil && verifies(pub, msg, sig)
	again := mk()
	pub2, err2 := again.PublicKey()
	sig2, err3 := again.Sign(msg)
	ok = ok && err2 == nil && err3 == nil && strings.EqualFold(hex.EncodeToString(pub), hex.EncodeToString(pub2)) && verifies(pub, msg, sig2)
	verdict(t, "CORE", ok, "the signer made, recorded, reopened and signed with a key of the profile's own name")

	// A key it did not make: same name, no authorization value.
	deleteTheKey(keyName)
	provider, _ := openProvider()
	n, _ := windows.UTF16PtrFromString(keyName)
	planted, perr := createMachineKey(provider, n, nil)
	if perr == nil {
		procFreeObject.Call(uintptr(planted))
	}
	procFreeObject.Call(uintptr(provider))
	third := mk()
	_, serr := third.Sign(msg)
	verdict(t, "CORE-OWN", perr == nil && !third.Available() && serr != nil,
		"a key of the profile's name made by someone else, with no authorization value, is refused (planting: "+fmt.Sprint(perr)+")")
	deleteTheKey(keyName)

	// Locked: the TPM is not asked at all.
	theGateIs(t, dir, aTestGate{profile, false})
	_, lerr := mk().Sign(msg)
	verdict(t, "CORE-LOCK", lerr != nil, "a locked profile's signer refuses: "+fmt.Sprint(lerr))
}

func probeCleanup(t *testing.T, st aProbeState, statePath string) {
	t.Helper()
	deleteTheKey(st.Name)
	_ = os.Remove(statePath)
	info("deleted the probe key %s", st.Name)
}
