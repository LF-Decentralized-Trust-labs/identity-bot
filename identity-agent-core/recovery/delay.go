package recovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	// MinCancelWindow is the launch-floor delay before recovery can complete.
	MinCancelWindow = 24 * time.Hour
)

// AssuranceBand maps identity assurance tiers to cancel-window durations.
type AssuranceBand string

const (
	BandRed   AssuranceBand = "red"
	BandAmber AssuranceBand = "amber"
	BandGreen AssuranceBand = "green"

	// BandUnknown is what an agent reports when nothing measured the band.
	//
	// It used to report amber in this case, which is a measurement somebody
	// could act on, produced by nothing having been measured. Every deployment
	// without a provider running therefore showed a graded assurance level that
	// was really a fallback constant — and it is the shorter of the two
	// available answers, so the guess erred towards less waiting rather than
	// more.
	BandUnknown AssuranceBand = "unknown"
)

// AuthProviderGate queries an AuthProvider for the current assurance band/score.
type AuthProviderGate interface {
	CurrentBand() (AssuranceBand, int, error)
}

// StubAuthProviderGate is a local stub until a live AuthProvider is wired.
type StubAuthProviderGate struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewStubAuthProviderGate() *StubAuthProviderGate {
	base := os.Getenv("AUTH_PROVIDER_URL")
	if base == "" {
		base = "http://127.0.0.1:9998"
	}
	return &StubAuthProviderGate{
		BaseURL:    base,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (g *StubAuthProviderGate) CurrentBand() (AssuranceBand, int, error) {
	if g == nil {
		return BandUnknown, 0, fmt.Errorf("no assurance provider configured")
	}
	client := g.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Get(g.BaseURL + "/score")
	if err != nil {
		// Unreachable is not a band. Reporting one here is how an agent with no
		// provider at all showed a graded assurance level to somebody.
		return BandUnknown, 0, fmt.Errorf("assurance provider unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return BandUnknown, 0, fmt.Errorf("auth provider score returned %d", resp.StatusCode)
	}
	var body struct {
		Band  string `json:"band"`
		Score int    `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return BandUnknown, 0, err
	}
	return AssuranceBand(body.Band), body.Score, nil
}

// CancelWindowForBand returns the assurance-graduated cancel-window delay.
//
// An unmeasured band gets the LONGEST window, not the shortest. The window is
// the time somebody who did not start this recovery has to stop it, so when
// nothing is known about the person asking, the answer that protects the owner
// is more time rather than less. The default arm used to return the minimum,
// which meant an agent that could not measure anything waited the least.
func CancelWindowForBand(band AssuranceBand) time.Duration {
	switch band {
	case BandGreen:
		return MinCancelWindow
	case BandAmber:
		return 48 * time.Hour
	case BandRed:
		return 72 * time.Hour
	default:
		return 72 * time.Hour
	}
}

// CancelWindowGate enforces the post-restore cancel window before activation.
type CancelWindowGate struct {
	AuthProvider AuthProviderGate
	Now          func() time.Time
}

func NewCancelWindowGate(auth AuthProviderGate) *CancelWindowGate {
	return &CancelWindowGate{
		AuthProvider: auth,
		Now:          time.Now,
	}
}

// Schedule computes when a recovery session may complete, honoring the 24h launch floor.
func (g *CancelWindowGate) Schedule(startedAt time.Time) (time.Time, time.Duration, AssuranceBand, error) {
	band, _, err := g.AuthProvider.CurrentBand()
	if err != nil {
		// Say it is unknown rather than substituting a band. The window this
		// produces is the longest one, so the caution is real rather than
		// cosmetic.
		band = BandUnknown
	}
	window := CancelWindowForBand(band)
	if window < MinCancelWindow {
		window = MinCancelWindow
	}
	return startedAt.Add(window), window, band, nil
}

// Remaining returns time until the cancel window elapses (zero if ready).
func (g *CancelWindowGate) Remaining(completeAfter time.Time) time.Duration {
	nowFn := g.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()
	if !completeAfter.After(now) {
		return 0
	}
	return completeAfter.Sub(now)
}

// ErrCancelWindowActive indicates recovery is still inside the cancel window.
type ErrCancelWindowActive struct {
	CompleteAfter time.Time
	Remaining     time.Duration
}

func (e *ErrCancelWindowActive) Error() string {
	return fmt.Sprintf("recovery cancel window active until %s (%s remaining)",
		e.CompleteAfter.UTC().Format(time.RFC3339), e.Remaining.Round(time.Second))
}
