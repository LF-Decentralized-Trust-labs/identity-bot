package secureenclave

// Whether an identity may live on THIS machine: the one verdict.
//
// THE QUESTION IS NOT WHETHER A KEY CAN BE PROTECTED HERE. That one has its own
// answer — RootKeyPermitted — and asking it instead is how a laptop came to
// found root identities. A Mac has a Secure Enclave, so it passes; and it still
// cannot tell anybody what software is using that key.
//
// The question is whether this machine can PROVE WHAT SOFTWARE IT RUNS to
// somebody who is not sitting at it. An identity is a claim other people rely
// on, and the software holding its keys is the thing that decides what it says.
//
// Three platforms can do it: iOS and Android, whose vendors attest the running
// application, and an AMD SEV-SNP sealed machine, which attests the whole guest.
// Nothing else — not macOS, where the attestation API reports unsupported and
// carrying its entitlement makes the application unlaunchable; not Windows,
// which has no mechanism for an ordinary user-mode application; not desktop
// Linux, which cannot do it for software distributed to the public.
//
// THIS LIVES HERE, BESIDE THE SEED CHECK, BECAUSE FOUNDING, INSTALLING AND
// RECOVERING A ROOT IDENTITY ARE ONE RULE. It used to sit in the server package,
// where the founding routes asked it and the root-seed install and recovery did
// not — so a production Mac, whose Secure Enclave is usable, could not found an
// identity and could still be handed one. CheckRootSeedMayLiveHere now asks it
// too, and the server's founding gate asks the same function.
//
// BEING REFUSED HERE IS NOT BEING REFUSED THE SOFTWARE. Any machine may run this
// application as a controller for an identity that lives somewhere it can be
// proved, and as somewhere backups are kept.

// FoundingVerdict is the platform's answer, with the reason when it is no.
//
// The reason is returned rather than logged because it is shown to a person who
// has just been stopped from doing the obvious thing, and "no" without "and
// here is what to do instead" is how somebody concludes the software is broken.
type FoundingVerdict struct {
	Permitted bool   `json:"permitted"`
	Platform  string `json:"platform"`
	Why       string `json:"why,omitempty"`
	// Instead names what this machine CAN do, so the refusal ends somewhere.
	Instead string `json:"instead,omitempty"`
}

// CannotProveItsSoftware is the reason given for every platform that cannot attest.
const CannotProveItsSoftware = "this computer cannot prove to anybody else " +
	"what software it is running, so an identity founded here could never be " +
	"checked by the people relying on it"

// ActForOneInstead is what a refused machine can still do.
const ActForOneInstead = "it can act for an identity kept on a machine that " +
	"can prove itself, and it can hold backups"

// foundingVerdictHere is a var so a test can stand in for the platform, the same
// way the seed wrapper and the capability detector are. The machines this is
// written to refuse are the machines it is developed on.
var foundingVerdictHere = foundingVerdictForThisPlatform

// MayFoundAnIdentityHere is the one place that decides, per platform in the
// files beside this one. dataDir is the directory the identity's state is
// actually written to: on a sealed machine the answer depends on that directory
// being on the encrypted volume, and the directory that matters is the one
// being written, not a default.
func MayFoundAnIdentityHere(dataDir string) FoundingVerdict { return foundingVerdictHere(dataDir) }

// UseFoundingVerdict replaces the platform's founding verdict and returns a
// function that puts the real one back. For tests.
func UseFoundingVerdict(f func() FoundingVerdict) (restore func()) {
	prev := foundingVerdictHere
	foundingVerdictHere = func(string) FoundingVerdict { return f() }
	return func() { foundingVerdictHere = prev }
}

// FoundingPermitted decides whether an identity may live here, given the
// platform's verdict and whether this is a development build. A development
// build may on a machine that cannot attest — the machines it is developed on
// are exactly the ones production refuses — and the identity it makes is a
// development-realm one that must never be relied on as a production one.
func FoundingPermitted(v FoundingVerdict, dev bool) bool {
	return v.Permitted || dev
}
