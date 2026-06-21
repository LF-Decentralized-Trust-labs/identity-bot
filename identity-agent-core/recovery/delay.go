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
	BandRed    AssuranceBand = "red"
	BandAmber  AssuranceBand = "amber"
	BandGreen  AssuranceBand = "green"
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
		return BandAmber, 60, nil
	}
	client := g.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Get(g.BaseURL + "/score")
	if err != nil {
		// Stub fallback — conservative delay when provider unreachable.
		return BandAmber, 60, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return BandAmber, 60, fmt.Errorf("auth provider score returned %d", resp.StatusCode)
	}
	var body struct {
		Band  string `json:"band"`
		Score int    `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return BandAmber, 60, err
	}
	return AssuranceBand(body.Band), body.Score, nil
}

// CancelWindowForBand returns the assurance-graduated cancel-window delay.
func CancelWindowForBand(band AssuranceBand) time.Duration {
	switch band {
	case BandGreen:
		return MinCancelWindow
	case BandAmber:
		return 48 * time.Hour
	case BandRed:
		return 72 * time.Hour
	default:
		return MinCancelWindow
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
		band = BandAmber
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