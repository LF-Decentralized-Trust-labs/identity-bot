package lockgate

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/login"
	"identity-agent-core/permission"
)

// ProviderResult is what a log-in through the authentication provider hands the
// gate. It is evidence to be checked, never an instruction: the gate decides.
type ProviderResult struct {
	Profile string             `json:"profile"`
	Level   authprovider.Level `json:"level"`
	Score   int                `json:"score"`
	At      time.Time          `json:"at"`
	Nonce   string             `json:"nonce"`
	// Provider names who answered. The placeholder is named as itself, so the
	// class of the lock cannot be mistaken (LockClass).
	Provider string `json:"provider,omitempty"`
	// Voucher is present on a desktop: the person's root device signed this
	// result over this machine. A machine may not score itself.
	Voucher *Voucher `json:"voucher,omitempty"`
}

// Voucher is a desktop's proof that its person's root device vouches for the
// result. Signature is over authprovider.CanonicalAuthLevelStatement.
type Voucher struct {
	AgentAID      string `json:"agent_aid"`
	ControllerAID string `json:"controller_aid"`
	Signature     string `json:"signature"`
}

// Mode says which kind of device this gate is on.
type Mode string

const (
	// ModePhone: the device holds the root, and the provider runs on it.
	ModePhone Mode = "root-device"
	// ModeController: a desktop, whose score must be vouched for.
	ModeController Mode = "controller"
)

// Refusal reasons. A caller can tell a person which, so none is a bare "no".
var (
	ErrWrongProfile = errors.New("this result is for a different identity")
	ErrBelowMinimum = errors.New("the measured score is below what logging in needs")
	ErrStale        = errors.New("this result is too old to log in with")
	ErrReplayed     = errors.New("this result was already used")
	ErrNoNonce      = errors.New("a log-in result needs a fresh nonce")
	ErrNeedsVoucher = errors.New("this computer may not score itself: its person's root device has to vouch for the result")
	ErrBadVoucher   = errors.New("the root device did not vouch for this result")
	ErrUnmeasured   = errors.New("nobody measured the person")
)

// MaxResultAge is how old a result may be, and how far in the future.
const (
	MaxResultAge   = 2 * time.Minute
	maxClockSkew   = 30 * time.Second
	minNonceLength = 16
	nonceMemory    = 4096
)

// Gate decides whether a profile's GK is released.
type Gate struct {
	Profile *Profile
	Mode    Mode
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// VerifyVoucher checks a desktop's voucher against the key of the device
	// entitled to vouch. Required in ModeController; a gate with none refuses
	// every desktop result rather than accepting an unchecked one.
	VerifyVoucher func(ProviderResult) error

	mu   sync.Mutex
	seen map[string]struct{}
	ring []string
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// Release returns the key that opens this profile, or says why not. It releases
// only if the result names this profile, is measured, scores at least
// permission.DefaultMinimumScore, is fresh, has not been used before, and (on a
// desktop) is vouched for. The returned key is the one that SEALS the profile:
// GK, or GK' when the owner set an identity secret, in which case secret must be
// right.
func (g *Gate) Release(r ProviderResult, secret string) (GK, error) {
	now := g.now()
	if r.Profile != g.Profile.ID() {
		return nil, ErrWrongProfile
	}
	if r.Level == authprovider.LevelUnknown || !r.Level.Known() {
		return nil, ErrUnmeasured
	}
	if r.Score < permission.DefaultMinimumScore {
		return nil, ErrBelowMinimum
	}
	if r.At.IsZero() || now.Sub(r.At) > MaxResultAge || r.At.Sub(now) > maxClockSkew {
		return nil, ErrStale
	}
	if len(r.Nonce) < minNonceLength {
		return nil, ErrNoNonce
	}
	if g.Mode == ModeController {
		if r.Voucher == nil || r.Voucher.Signature == "" {
			return nil, ErrNeedsVoucher
		}
		if g.VerifyVoucher == nil {
			return nil, ErrBadVoucher
		}
		if err := g.VerifyVoucher(r); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadVoucher, err)
		}
	}
	// Spend the nonce before any key is touched, so a result is good for one
	// try even if the try fails later.
	if !g.spend(r.Nonce) {
		return nil, ErrReplayed
	}
	base, err := g.Profile.readGateCopy()
	if err != nil {
		return nil, err
	}
	eff, err := g.Profile.effective(base, secret, now)
	if err != nil {
		base.Zero()
		return nil, err
	}
	if len(eff) > 0 && &eff[0] != &base[0] {
		base.Zero()
	}
	return eff, nil
}

func (g *Gate) spend(nonce string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]struct{}{}
	}
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = struct{}{}
	g.ring = append(g.ring, nonce)
	if len(g.ring) > nonceMemory {
		delete(g.seen, g.ring[0])
		g.ring = g.ring[1:]
	}
	return true
}

// VoucherFromRootDevice builds the check a desktop's gate uses: the voucher's
// signature must verify, under the key rootDeviceKey names, over the statement
// the controller-request path already uses for the same purpose.
// rootDeviceKey returns the verkey of the device entitled to vouch, or an error
// when this agent knows of none (then every result is refused).
func VoucherFromRootDevice(rootDeviceKey func() (string, error), thisAgent, thisMachine func() string) func(ProviderResult) error {
	return func(r ProviderResult) error {
		v := r.Voucher
		if v == nil {
			return errors.New("no voucher")
		}
		// Bound to this agent and this machine: a voucher made for another
		// desktop of the same person does not open this one.
		if thisAgent == nil || thisMachine == nil || v.AgentAID != thisAgent() || thisMachine() == "" || v.ControllerAID != thisMachine() {
			return errors.New("the voucher is not for this agent and this machine")
		}
		key, err := rootDeviceKey()
		if err != nil || key == "" {
			return errors.New("this agent knows of no device entitled to vouch")
		}
		pub, err := login.DecodeVerkey(key)
		if err != nil {
			return errors.New("the vouching device's key is unusable")
		}
		ok, err := login.VerifyString(
			authprovider.CanonicalAuthLevelStatement(v.AgentAID, v.ControllerAID, r.Level, r.At, r.Score),
			v.Signature, pub)
		if err != nil || !ok {
			return errors.New("the signature does not verify")
		}
		return nil
	}
}

// LockClass says what a lock is worth, derived and never inferred (ADR-074
// section 4).
type LockClass string

const (
	// ClassNone: the profile has no gate (made before one existed); it is not locked
	// by anything, and says so.
	ClassNone LockClass = "none"
	// ClassAppOnly: the gate is satisfied by a placeholder provider.
	ClassAppOnly LockClass = "app_only"
	// ClassSecretBound: the owner set the optional identity secret.
	ClassSecretBound LockClass = "secret_bound"
	// ClassProviderBound: a real provider's answer released GK. Nothing in this
	// package can reach it yet: it needs a provider whose answer the gate copy is
	// sealed under, and the gate copy is not. It is named so no screen invents it.
	ClassProviderBound LockClass = "provider_bound"
)

// Class is the profile's lock class.
func (p *Profile) Class() LockClass {
	r, err := p.readRecord()
	if err != nil {
		return ClassNone
	}
	if r.Secret != nil {
		return ClassSecretBound
	}
	return ClassAppOnly
}
