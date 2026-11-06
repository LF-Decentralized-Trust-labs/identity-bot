package secureenclave

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Which app the key was made for.
//
// An attestation records the application that asked the Keystore for the key
// (attestationApplicationId): its package name and the SHA-256 digests of the
// certificates it is signed with. A chain made for some other app, or for a
// repackaged copy of this one, is a chain for a key that app controls, so the
// core compares the record with the app this core was built for and refuses a
// mismatch.
//
// Where the expected identity comes from. It is built into the core, not
// declared by the app at runtime. Whoever builds the app's core sets it with
// two linker flags (like buildmode.rawMode):
//
//	gomobile bind -ldflags "-X identity-agent-core/secureenclave.builtAppPackage=<package name> \
//	  -X identity-agent-core/secureenclave.builtAppSignerDigests=<sha256 hex>[,<sha256 hex>...]" ...
//
// builtAppPackage is the app's package name. builtAppSignerDigests is the
// SHA-256 digest, in hex, of each certificate the app may be signed with,
// separated by commas and no spaces (colons inside a digest are ignored); list
// the old and the new while a signing key is rotated. Nothing else writes them.
//
// Why a build-time value. An app asked at runtime takes its package name and
// signing digests from the system (PackageInfo), which answers for whichever
// app is running: a repackaged copy, re-signed by someone else, would declare
// the someone-else and pass. A value compiled into the core names the app the
// builder meant, so a copy signed with any other key is refused.
//
// A production build with no built identity refuses every attestation and says
// how to set it (fail closed). A development build without one accepts the
// app's runtime declaration (DeclareAppIdentity), and the facts and the log say
// the identity was declared at runtime, not built in. When an identity is
// built in, a runtime declaration is ignored in every build.
var (
	builtAppPackage       string
	builtAppSignerDigests string
)

// What the app declared at runtime (development builds only, see above).
var (
	appIdentityMu       sync.RWMutex
	appPackage          string
	appSignerDigests    [][]byte
	appIdentityDeclared bool
	runtimeIdentityLog  sync.Once
)

// DeclareAppIdentity registers, at runtime, the package name and the SHA-256
// digests of the signing certificates the app declares (every certificate it
// may be signed with, so a rotation lists the old and the new). Called before
// the server starts. Digests are 32 bytes each. It is used only by a
// development build with no identity built in; see builtAppPackage.
func DeclareAppIdentity(packageName string, signerDigests [][]byte) error {
	cp, err := checkedIdentity(packageName, signerDigests)
	if err != nil {
		return err
	}
	appIdentityMu.Lock()
	appPackage, appSignerDigests, appIdentityDeclared = packageName, cp, true
	appIdentityMu.Unlock()
	return nil
}

func checkedIdentity(packageName string, signerDigests [][]byte) ([][]byte, error) {
	if packageName == "" || len(signerDigests) == 0 {
		return nil, fmt.Errorf("an app identity needs a package name and at least one signing certificate digest")
	}
	cp := make([][]byte, 0, len(signerDigests))
	for _, d := range signerDigests {
		if len(d) != 32 {
			return nil, fmt.Errorf("a signing certificate digest is %d bytes, not 32", len(d))
		}
		cp = append(cp, append([]byte(nil), d...))
	}
	return cp, nil
}

// ClearAppIdentity removes the runtime declaration.
func ClearAppIdentity() {
	appIdentityMu.Lock()
	appPackage, appSignerDigests, appIdentityDeclared = "", nil, false
	appIdentityMu.Unlock()
}

const buildAppIdentityHow = "set it when building the app's core with " +
	`-ldflags "-X identity-agent-core/secureenclave.builtAppPackage=<package name> ` +
	`-X identity-agent-core/secureenclave.builtAppSignerDigests=<sha256 hex>[,<sha256 hex>...]"`

// expectedAppIdentity is the app the attestation must name, and a note when it
// is only the app's own runtime word (a development build with none built in).
func expectedAppIdentity() (pkg string, digests [][]byte, note string, err error) {
	if builtAppPackage != "" || builtAppSignerDigests != "" {
		d, perr := ParseSignerDigests(builtAppSignerDigests)
		if perr == nil {
			d, perr = checkedIdentity(builtAppPackage, d)
		}
		if perr != nil {
			return "", nil, "", notAttested("the app identity built into this core is not usable (%v); %s", perr, buildAppIdentityHow)
		}
		return builtAppPackage, d, "", nil
	}
	if !isDevBuild() {
		return "", nil, "", notAttested("this production build has no app identity built in, so the attestation " +
			"cannot be held to the app it was made for; " + buildAppIdentityHow)
	}
	appIdentityMu.RLock()
	pkg, digests, declared := appPackage, appSignerDigests, appIdentityDeclared
	appIdentityMu.RUnlock()
	if !declared {
		return "", nil, "", notAttested("the app has not declared its package name and signing certificates, " +
			"so the attestation cannot be held to the app it was made for; " + buildAppIdentityHow)
	}
	note = "the app identity was declared by the app at runtime, not built into the core, " +
		"so a repackaged app would pass this check"
	runtimeIdentityLog.Do(func() { log.Printf("[keystore] development build: %s", note) })
	return pkg, digests, note, nil
}

// ParseSignerDigests reads hex SHA-256 digests separated by commas, semicolons,
// spaces or newlines (colons inside a digest are ignored), the form gomobile can carry (it cannot pass [][]byte).
func ParseSignerDigests(list string) ([][]byte, error) {
	var out [][]byte
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		d, err := hex.DecodeString(strings.ReplaceAll(f, ":", ""))
		if err != nil {
			return nil, fmt.Errorf("%q is not a hex digest", f)
		}
		out = append(out, d)
	}
	return out, nil
}

// checkAppIdentity compares what the attestation says about the requesting app
// with the app this core was built for. Nothing to compare with is a refusal,
// not a pass. A development build's runtime declaration is noted in
// f.AppIdentityNote.
func checkAppIdentity(f *AndroidKeyFacts) error {
	pkg, digests, note, err := expectedAppIdentity()
	if err != nil {
		return err
	}
	if !f.AppIDPresent {
		return notAttested("the attestation does not say which app asked for the key")
	}
	if len(f.AppPackages) != 1 || f.AppPackages[0] != pkg {
		return notAttested("the key was made for the app %q, not for %q", strings.Join(f.AppPackages, ", "), pkg)
	}
	if len(f.AppSignerDigests) == 0 {
		return notAttested("the attestation names no signing certificate for the app")
	}
	for _, got := range f.AppSignerDigests {
		ok := false
		for _, want := range digests {
			if bytes.Equal(got, want) {
				ok = true
				break
			}
		}
		if !ok {
			return notAttested("the key was made for an app signed with a certificate (%x) this app does not declare", got)
		}
	}
	f.AppIdentityNote = note
	return nil
}
