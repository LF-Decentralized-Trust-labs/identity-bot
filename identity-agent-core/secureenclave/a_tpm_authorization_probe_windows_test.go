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
// DELETE and CORE-DELETE are the claim that a key with an authorization value can be
// deleted by the core's own delete (deleteMachineKey, the one takeBack uses): the
// provider wants the value before it deletes such a key, and a delete that is refused
// leaves the key behind. SWEEP and CLEAN are the probe's own housekeeping, said as
// claims so a key it cannot remove stops "ALL PASS": SWEEP at the start (keys an earlier
// run left), CLEAN at the end (nothing of this run is left). A delete that does not happen
// is a FAIL naming the key, never ignored.
//
// HOW TO RUN: scripts/tpm-authorization-probe.ps1 (from a Windows PowerShell,
// in the identity-bot checkout, on a machine with a TPM 2.0). It compiles this
// file with `go test -c -tags tpmprobe`, runs it in your session, then again as a
// scheduled task with no desktop (which is what the core is), and prints the
// verdict.
//
// NOTE: LOCKOUT only means something if the provider's keys are under the TPM's
// dictionary-attack protection. If the counter does not rise, that is the finding:
// the design may not count on the TPM to limit guesses. The "no desktop" run adds
// a different logon token, not proof of no desktop (NCRYPT_SILENT_FLAG already
// forbids prompting in your own session).
//
// COST: the probe sends ONE wrong value and ONE missing value to a key of its own.
// A TPM counts failed authorizations toward a lockout it shares with everything
// else on the machine, Windows Hello included. The probe reads the counter first
// and stops without trying if fewer than 3 failures remain. It deletes its keys.
//
// Phases, by PROBE_PHASE (the script sets them; "all" is the default):
//
//	all      create, sign, refuse, core, cleanup, in one process
//	sweep    delete the probe keys an earlier run left (by name, never by a pattern of the core's)
//	create   make the probe key, write PROBE_STATE (a throwaway value, in a file)
//	sign     sign with the right value from PROBE_STATE (the non-interactive check)
//	refuse   try the wrong value and no value, and read the lockout counter
//	core     the tpmSigner end to end
//	delete   make a key with a value, delete it as the core does, and check it is gone
//	cleanup  delete the probe key, and check nothing of the probe is left

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		probeSweep(t)
		st := probeCreate(t, statePath)
		probeSign(t, st, "in this process")
		probeRefuse(t, st)
		probeDelete(t)
		probeCore(t)
		probeCleanup(t, statePath)
	case "sweep":
		probeSweep(t)
	case "create":
		probeCreate(t, statePath)
	case "sign":
		probeSign(t, readProbeState(t, statePath), "from a process with no desktop")
	case "refuse":
		probeRefuse(t, readProbeState(t, statePath))
	case "delete":
		probeDelete(t)
	case "core":
		probeCore(t)
	case "cleanup":
		probeCleanup(t, statePath)
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
	if t != nil {
		t.Helper()
	}
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

// ---- keys the probe makes, and taking them away --------------------------------

// The probe's own keys are named so that what is needed to delete one follows from
// its name alone: a key left by a crash is deleted by the next run, which has no state
// file and no memory of it. Nothing here ever deletes a key by the core's name pattern,
// since a real profile's key has it too; the core's probe key has the one fixed
// profile id below, which no real profile has.
const (
	// Keys made by this version carry the versioned prefix, and only they are swept:
	// their value follows from their name. A key with the older prefix was made by an
	// earlier version with a random value that was never written down, so the sweep
	// never tries it (a wrong value counts against the TPM's lockout counter, which
	// Windows Hello shares): it is reported, with the command to delete it by hand.
	theProbeKeyPrefix    = "IdentityAgentAuthProbe.v2."
	theOldProbeKeyPrefix = "IdentityAgentAuthProbe."
	theCoreProbeProfile  = "identity-agent-tpm-probe-core"
	certutilDeleteAdvice = `delete it by hand: certutil -user -csp "Microsoft Platform Crypto Provider" -delkey `
)

func probeAuthFor(name string) []byte {
	sum := sha256.Sum256([]byte("tpm authorization probe value|" + name))
	return sum[:tpmAuthLen]
}

func theCoreProbeKeyName() string { return ProfileKeyName(machineKeyName, theCoreProbeProfile) }

// theCoreProbeAuth is the value the core derives for the probe's profile, with the
// test gate the probe installs.
func theCoreProbeAuth() []byte {
	v, _ := aTestGate{theCoreProbeProfile, true}.DeriveKey(tpmAuthInfo, tpmAuthLen)
	return v
}

// theKeyIs says whether the provider holds a key of this name, or why it cannot say.
func theKeyIs(name string) (bool, error) {
	provider, err := openProvider()
	if err != nil {
		return false, err
	}
	defer procFreeObject.Call(uintptr(provider))
	key, st := openTheKey(nil, provider, name)
	switch {
	case st == 0:
		procFreeObject.Call(uintptr(key))
		return true, nil
	case meansNoKeyYet(st):
		return false, nil
	}
	return false, fmt.Errorf("the provider would not say whether %s exists (0x%X)", name, st)
}

// removeTheKey deletes the named key as the core deletes one (deleteMachineKey) and
// checks it is gone. Absent is fine and says so (false); a delete that does not happen is
// an error that names the key.
func removeTheKey(name string, auth []byte) (wasThere bool, err error) {
	there, err := theKeyIs(name)
	if err != nil || !there {
		return false, err
	}
	provider, err := openProvider()
	if err != nil {
		return true, err
	}
	defer procFreeObject.Call(uintptr(provider))
	key, st := openTheKey(nil, provider, name)
	if st != 0 {
		return true, fmt.Errorf("%s would not open to be deleted (0x%X): %s%s", name, st, certutilDeleteAdvice, name)
	}
	if err := deleteMachineKey(key, auth); err != nil {
		procFreeObject.Call(uintptr(key)) // a refused delete leaves the handle ours
		return true, fmt.Errorf("%s: %v: %s%s", name, err, certutilDeleteAdvice, name)
	}
	if still, err := theKeyIs(name); err != nil || still {
		return true, fmt.Errorf("%s is still in the TPM after its delete reported success: %s%s", name, certutilDeleteAdvice, name)
	}
	return true, nil
}

var (
	procEnumKeys   = ncrypt.NewProc("NCryptEnumKeys")
	procFreeBuffer = ncrypt.NewProc("NCryptFreeBuffer")
)

const nteNoMoreItems = 0x8009002A

type aKeyName struct { // NCryptKeyName
	name, algid *uint16
	legacySpec  uint32
	flags       uint32
}

// theProbeKeysInTheTPM lists the keys this version of the probe made and left, by name.
func theProbeKeysInTheTPM() ([]string, error) {
	names, _, err := theProbeKeysByAge()
	return names, err
}

// theProbeKeysByAge lists the probe's keys by name: those with this version's prefix
// (which the probe can delete) and those with an earlier version's (which it cannot,
// and never tries).
func theProbeKeysByAge() (current, older []string, err error) {
	provider, err := openProvider()
	if err != nil {
		return nil, nil, err
	}
	defer procFreeObject.Call(uintptr(provider))
	var state uintptr
	defer func() {
		if state != 0 {
			procFreeBuffer.Call(state)
		}
	}()
	for {
		var kn *aKeyName
		r, _, _ := procEnumKeys.Call(uintptr(provider), 0, uintptr(unsafe.Pointer(&kn)), uintptr(unsafe.Pointer(&state)), ncryptSilentFlag)
		if uint32(r) == nteNoMoreItems {
			return current, older, nil
		}
		if r != 0 {
			return current, older, fmt.Errorf("the provider's keys could not be listed (0x%X)", uint32(r))
		}
		n := windows.UTF16PtrToString(kn.name)
		procFreeBuffer.Call(uintptr(unsafe.Pointer(kn)))
		switch {
		case strings.HasPrefix(n, theProbeKeyPrefix):
			current = append(current, n)
		case strings.HasPrefix(n, theOldProbeKeyPrefix):
			older = append(older, n)
		}
	}
}

// theProbesKeysAreRemoved deletes every key the probe could have made: the ones named
// with its prefix and the core's probe key. It gives the number it found and what it
// could not remove.
func theProbesKeysAreRemoved() (found int, problems []string) {
	left, err := theProbeKeysInTheTPM()
	if err != nil {
		problems = append(problems, err.Error())
	}
	for _, n := range left {
		if was, err := removeTheKey(n, probeAuthFor(n)); err != nil {
			problems = append(problems, err.Error())
		} else if was {
			found++
		}
	}
	if was, err := removeTheKey(theCoreProbeKeyName(), theCoreProbeAuth()); err != nil {
		problems = append(problems, err.Error())
	} else if was {
		found++
	}
	return found, problems
}

// ---- the phases ---------------------------------------------------------------

func probeCreate(t *testing.T, statePath string) aProbeState {
	t.Helper()
	var rnd [8]byte
	rand.Read(rnd[:])
	// The value follows from the name (probeAuthFor), so a key a crash leaves is one
	// the next run can delete without a state file.
	keyName := theProbeKeyPrefix + hex.EncodeToString(rnd[:])
	auth := probeAuthFor(keyName)
	st := aProbeState{Name: keyName, Auth: hex.EncodeToString(auth)}

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

// probeSweep removes what an earlier run left, and says so if it cannot: a key that
// stays is a FAIL naming it, and the run is not "ALL PASS".
func probeSweep(t *testing.T) {
	t.Helper()
	// Read first, delete second: older keys are only named, never opened or deleted.
	if _, older, err := theProbeKeysByAge(); err == nil {
		for _, n := range older {
			info("an earlier version of the probe left the key %s; its value is lost, so it is not tried. It is unused and harmless to leave. To remove it anyway, %s%s (it may ask for the value; cancelling costs nothing)", n, certutilDeleteAdvice, n)
		}
	}
	found, problems := theProbesKeysAreRemoved()
	if len(problems) > 0 {
		verdict(t, "SWEEP", false, "a key an earlier run left could not be removed: "+strings.Join(problems, "; "))
		return
	}
	verdict(t, "SWEEP", true, fmt.Sprintf("%d key(s) left by earlier runs removed; none remain", found))
}

// probeDelete is the claim that a key made with an authorization value is deleted by the
// core's own delete. The provider needs the value before it deletes such a key; a
// delete made silently (as the core's must be) without it is refused and the key stays.
// The delete is made from a fresh open, as a later process would make it.
func probeDelete(t *testing.T) {
	t.Helper()
	var rnd [8]byte
	makeOne := func() (string, error) {
		rand.Read(rnd[:])
		name := theProbeKeyPrefix + "delete." + hex.EncodeToString(rnd[:])
		provider, err := openProvider()
		if err != nil {
			return "", err
		}
		defer procFreeObject.Call(uintptr(provider))
		n, _ := windows.UTF16PtrFromString(name)
		key, err := createMachineKey(provider, n, probeAuthFor(name))
		if err != nil {
			return name, err
		}
		procFreeObject.Call(uintptr(key))
		return name, nil
	}
	name, err := makeOne()
	if err != nil {
		verdict(t, "DELETE", false, "NOT RUN: a key with an authorization value could not be made to delete: "+err.Error())
		return
	}
	// What the provider does without the value, for the record. A delete that goes
	// through here is a finding too (the value is not what guards the delete), and
	// leaves nothing to delete as the core does, so another key is made.
	// It may count one failure against the TPM's lockout counter, so it is made only
	// when at least 3 remain, as in WRONG and NONE.
	provider, perr := openProvider()
	before, haveBefore := theTPMProperty(theLockoutCounter)
	max, haveMax := theTPMProperty(theLockoutMaxFails)
	if !haveBefore || !haveMax || max-before < 3 {
		info("the delete with no authorization value is not tried: the lockout counter is unknown or fewer than 3 failures remain")
		if perr == nil {
			procFreeObject.Call(uintptr(provider))
			perr = errors.New("skipped")
		}
	}
	if perr == nil {
		if key, st := openTheKey(t, provider, name); st == 0 {
			if r, _, _ := procDeleteKey.Call(uintptr(key), ncryptSilentFlag); r != 0 {
				info("a silent delete with no authorization value: refused (0x%X), and the key stays", uint32(r))
				procFreeObject.Call(uintptr(key))
			} else {
				info("a silent delete with no authorization value WAS accepted: the provider does not ask for it to delete")
			}
		}
		procFreeObject.Call(uintptr(provider))
	}
	if there, _ := theKeyIs(name); !there {
		if name, err = makeOne(); err != nil {
			verdict(t, "DELETE", false, "NOT RUN: a second key could not be made: "+err.Error())
			return
		}
	}
	_, err = removeTheKey(name, probeAuthFor(name))
	verdict(t, "DELETE", err == nil, "a key made with an authorization value is deleted by the core's own delete, with the value and no prompt, and is gone afterwards"+
		map[bool]string{true: "", false: ": " + fmt.Sprint(err)}[err == nil])
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

	// A refusal only counts when the key demonstrably opens and signs first, and
	// when it is the signing that is refused: a bad handle or a failed open is
	// not the TPM refusing an authorization value.
	if _, status, at := signWith(t, st.Name, auth, msg); status != 0 {
		verdict(t, "WRONG", false, fmt.Sprintf("NOT RUN: the right value fails first at %q (0x%X)", at, status))
		verdict(t, "NONE", false, "NOT RUN, as above")
		return
	}
	refusedAtSigning := func(at string) bool { return at == "sign" || at == "size the signature" }

	before, haveBefore := theTPMProperty(theLockoutCounter)
	max, haveMax := theTPMProperty(theLockoutMaxFails)
	if haveBefore && haveMax {
		info("TPM lockout counter %d of %d", before, max)
		if max-before < 3 {
			verdict(t, "WRONG", false, "NOT RUN: fewer than 3 failed authorizations remain before the TPM locks; wait for the counter to fall and run again")
			verdict(t, "NONE", false, "NOT RUN, as above")
			return
		}
	} else if os.Getenv("PROBE_ALLOW_BLIND") != "1" {
		verdict(t, "WRONG", false, "NOT RUN: the lockout counter cannot be read here, so the probe cannot promise not to lock the TPM; set PROBE_ALLOW_BLIND=1 to accept that")
		verdict(t, "NONE", false, "NOT RUN, as above")
		return
	} else {
		info("the TPM lockout counter cannot be read from this process, so LOCKOUT will be reported as UNKNOWN")
	}

	_, status, at := signWith(t, st.Name, wrong, msg)
	verdict(t, "WRONG", status != 0 && refusedAtSigning(at), fmt.Sprintf("the wrong value: status 0x%X at %q (a refusal at signing is the TPM refusing)", status, at))
	mid, haveMid := theTPMProperty(theLockoutCounter)

	_, status, at = signWith(t, st.Name, nil, msg)
	// 0x80090022 is NTE_SILENT_CONTEXT: the provider wanted to ask a person. That
	// is a refusal, and is what no value looks like in a process that may not prompt.
	verdict(t, "NONE", status != 0 && refusedAtSigning(at), fmt.Sprintf("no value: status 0x%X at %q (refused at signing, without waiting for a prompt)", status, at))
	after, haveAfter := theTPMProperty(theLockoutCounter)

	switch {
	case !haveBefore || !haveMid || !haveAfter:
		line := "PROBE LOCKOUT  UNKNOWN  the counter could not be read; read TPM_PT_LOCKOUT_COUNTER by hand (tpmtool or Get-Tpm) before and after a refusal"
		fmt.Println(line)
		theProbeVerdicts = append(theProbeVerdicts, line)
	default:
		verdict(t, "LOCKOUT", mid > before, fmt.Sprintf("the counter went %d -> %d after the wrong value, and %d after no value. If it did not rise, PCP keys here are exempt from the TPM's lockout, which the design must not count on", before, mid, after))
	}

	// And the right value still works afterwards: a refusal did not break the key.
	if sig, status, at := signWith(t, st.Name, auth, msg); status != 0 {
		verdict(t, "SIGN2", false, fmt.Sprintf("after the refusals the right value failed at %q (0x%X)", at, status))
	} else {
		pub, _ := hex.DecodeString(st.Pub)
		verdict(t, "SIGN2", verifies(pub, msg, sig), "the right value still signs after the refusals")
	}
}

// probeCore runs the tpmSigner itself, for a profile whose gate is a test gate. The
// profile is the one fixed id (theCoreProbeProfile), so its key has a name a sweep can
// find, and its value follows from the test gate.
func probeCore(t *testing.T) {
	t.Helper()
	profile := theCoreProbeProfile
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{profile, true})
	keyName := ProfileKeyName(machineKeyName, profile)
	// Taken away at the end whatever happened; if that fails the probe's CLEAN says so
	// and names the key.
	defer func() {
		if _, err := removeTheKey(keyName, theCoreProbeAuth()); err != nil {
			info("the core's probe key could not be removed at the end of the core phase: %v", err)
		}
	}()
	if _, err := removeTheKey(keyName, theCoreProbeAuth()); err != nil {
		verdict(t, "CORE", false, "NOT RUN: a key of the core probe's name is already there and cannot be removed: "+err.Error())
		return
	}

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

	// Deleting a profile's key, which has an authorization value: by the value the core
	// derives for it, silently, and the key is gone.
	auth, aerr := tpmAuthorizationFor(dir)
	_, derr := removeTheKey(keyName, auth)
	gone, gerr := theKeyIs(keyName)
	verdict(t, "CORE-DELETE", aerr == nil && derr == nil && gerr == nil && !gone,
		fmt.Sprintf("the profile's key, made under its gate's authorization value, is deleted by the core's own delete with no prompt (value: %v, delete: %v, still there: %v)", aerr, derr, gone))

	// A key it did not make: same name, no authorization value.
	provider, _ := openProvider()
	n, _ := windows.UTF16PtrFromString(keyName)
	planted, perr := createMachineKey(provider, n, nil)
	var plantedPub []byte
	if perr == nil {
		plantedPub, _ = exportPublic(planted)
		procFreeObject.Call(uintptr(planted))
	}
	// What the provider says about the name now, before the signer looks: the signer
	// treats some statuses as "no key yet", and this shows which one it would see.
	if k, st := openTheKey(t, provider, keyName); st == 0 {
		reopened, _ := exportPublic(k)
		procFreeObject.Call(uintptr(k))
		info("the planted key opens by name (status 0); it is the planted one: %v", bytes.Equal(reopened, plantedPub))
	} else {
		info("the planted key does NOT open by name: status 0x%X", st)
	}
	procFreeObject.Call(uintptr(provider))
	third := mk()
	_, serr := third.Sign(msg)
	info("after the signer looked: available %v, sign error %v, its key is the planted one: %v, its key is new: %v",
		third.Available(), serr, len(third.pub) > 0 && bytes.Equal(third.pub, plantedPub), len(third.pub) > 0 && !bytes.Equal(third.pub, plantedPub))
	if there, err := theKeyIs(keyName); err == nil {
		info("a key of the profile's name is listed afterwards: %v", there)
	}
	_, rerr := removeTheKey(keyName, nil)
	verdict(t, "CORE-OWN", perr == nil && !third.Available() && (errors.Is(serr, ErrControllerKeyNotOurs) || errors.Is(serr, errAHardwareKeyExistsAndWillNotOpen)),
		"a key of the profile's name made by someone else, with no authorization value, is refused (planting: "+fmt.Sprint(perr)+"; removing it afterwards: "+fmt.Sprint(rerr)+")")

	// Locked: the TPM is not asked at all.
	theGateIs(t, dir, aTestGate{profile, false})
	_, lerr := mk().Sign(msg)
	verdict(t, "CORE-LOCK", errors.Is(lerr, ErrIdentityLocked), "a locked profile's signer refuses: "+fmt.Sprint(lerr))
}

// probeCleanup removes every key the probe could have made, whichever phase made it
// and whether or not an earlier phase failed, and checks that none is left. CLEAN fails,
// naming each key, when one is.
func probeCleanup(t *testing.T, statePath string) {
	t.Helper()
	found, problems := theProbesKeysAreRemoved()
	_ = os.Remove(statePath)
	if left, err := theProbeKeysInTheTPM(); err != nil {
		problems = append(problems, err.Error())
	} else if len(left) > 0 {
		problems = append(problems, "still listed: "+strings.Join(left, ", "))
	}
	if there, err := theKeyIs(theCoreProbeKeyName()); err != nil || there {
		problems = append(problems, "the core probe's key "+theCoreProbeKeyName()+" is still there")
	}
	if len(problems) > 0 {
		verdict(t, "CLEAN", false, "a key the probe made is still in the TPM: "+strings.Join(problems, "; "))
		return
	}
	verdict(t, "CLEAN", true, fmt.Sprintf("%d key(s) removed; none of the probe's remain", found))
}
