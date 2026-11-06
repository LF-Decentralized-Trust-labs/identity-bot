package secureenclave

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"identity-agent-core/internal/atomicfile"
)

// Google's attestation revocation list.
//
// A chain that ends at Google's root proves a key lives in hardware only while
// the attestation keys Google put in that hardware stay secret. When one leaks,
// whoever holds it can sign a chain for a key they keep in software and have it
// read as StrongBox. Google publishes the serial numbers of the certificates it
// has withdrawn at https://android.googleapis.com/attestation/status:
//
//	{"entries": {"<serial, lower-case hex>": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}, ...}}
//
// status is REVOKED or SUSPENDED; the list is public, about 180 kB, served with
// max-age=86400 and not signed, so what vouches for it is the TLS connection to
// Google, checked against the system roots. The serial numbers are those of every
// certificate in a chain, so each one is looked up.
//
// WHAT IS SENT. One GET of the whole list, with no query, no cookies, no
// credentials and no User-Agent. Nothing about the phone, the app, the key or
// the chain is in the request, and the list is fetched whole so that Google
// cannot tell which serial numbers were looked up.
//
// WHEN IT IS FETCHED. Not per credential and not per check: the list is kept in
// memory and refreshed at most once a day (Google's own max-age), and a failed
// fetch is not retried for a quarter of an hour, so a phone with no network does
// not wait on a connection every time the question is asked.
//
// WHEN IT CANNOT BE FETCHED. The copy kept in the data directory (with the time
// it was fetched) is used while it is under seven days old. With no list that
// young, a production build refuses the chain and says why; a development build
// lets it through and records, in the facts and in the log, that it was not
// checked.
//
// WHAT A LISTED SERIAL DOES. A REVOKED or SUSPENDED certificate anywhere in the
// chain refuses it, in every build: that is Google saying the key is not to be
// trusted, and it is not a question of whether a list was reachable.

const (
	googleAttestationStatusURL = "https://android.googleapis.com/attestation/status"

	// statusListRefresh is how old the list may be before an online core fetches
	// it again; statusListUsableFor is how old a copy may be and still be used
	// when it cannot.
	statusListRefresh   = 24 * time.Hour
	statusListUsableFor = 7 * 24 * time.Hour
	// statusFetchBackoff is how long after a failed fetch the core does not try again.
	statusFetchBackoff = 15 * time.Minute
	statusFetchTimeout = 15 * time.Second
	statusListMaxBytes = 16 << 20
	// statusListShrinkLimit: a fetched list with fewer entries than this
	// fraction of the copy held is not believed while that copy is usable.
	// Google's list only grows in practice, so a list that has lost more than
	// half its entries is a truncated or substituted answer, not a mass
	// un-revocation.
	statusListShrinkLimit = 0.5

	statusCacheFile = "android_attestation_status.json"
)

// ErrAttestationRevoked: a certificate in the chain is on Google's list.
var ErrAttestationRevoked = fmt.Errorf("%w: a certificate in the chain is revoked", ErrNotAttested)

// ErrNoStatusList: there is no usable copy of Google's list, so the chain cannot
// be checked against it.
var ErrNoStatusList = errors.New("Google's attestation revocation list is not available")

// fetchStatusList gets the list. A variable so tests can stand Google's server.
var fetchStatusList = func(ctx context.Context) ([]byte, error) {
	return fetchStatusListFrom(ctx, statusHTTPClient, googleAttestationStatusURL)
}

// statusHTTPClient follows no redirects and keeps no cookies.
var statusHTTPClient = &http.Client{
	Timeout: statusFetchTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func fetchStatusListFrom(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// An empty value makes net/http leave the header out (it would otherwise
	// send "Go-http-client/1.1").
	req.Header.Set("User-Agent", "")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, statusListMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > statusListMaxBytes {
		return nil, errors.New("the list is larger than any real one")
	}
	return body, nil
}

// statusEntry is one listed certificate.
type statusEntry struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// statusList is Google's list and when this core fetched it.
type statusList struct {
	Fetched time.Time              `json:"fetched"`
	Entries map[string]statusEntry `json:"entries"`
}

// serialKey spells a serial number the way the list does.
func serialKey(n *big.Int) string { return strings.ToLower(n.Text(16)) }

// parseStatusList checks that body is Google's list and nothing else (an error
// page, a captive portal's HTML or a truncated download is not an empty list of
// revocations) and normalises the serial numbers.
func parseStatusList(body []byte, fetched time.Time) (*statusList, error) {
	var raw struct {
		Entries map[string]statusEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("not Google's list: %w", err)
	}
	if len(raw.Entries) == 0 {
		// Google's list has never been empty; an empty one would revoke nothing
		// and read as "every chain is clean".
		return nil, errors.New("not Google's list: it has no entries")
	}
	l := &statusList{Fetched: fetched, Entries: make(map[string]statusEntry, len(raw.Entries))}
	for k, e := range raw.Entries {
		n, ok := new(big.Int).SetString(strings.TrimSpace(k), 16)
		if !ok || n.Sign() < 0 {
			return nil, fmt.Errorf("not Google's list: %q is not a serial number", k)
		}
		if e.Status == "" {
			return nil, fmt.Errorf("not Google's list: entry %q has no status", k)
		}
		l.Entries[serialKey(n)] = e
	}
	return l, nil
}

// check refuses a chain any of whose certificates the list names. Any entry
// refuses, not only REVOKED and SUSPENDED: a status Google adds later is no
// reason to trust the certificate it is attached to.
func (l *statusList) check(serials []string) error {
	for i, s := range serials {
		if e, listed := l.Entries[s]; listed {
			why := e.Status
			if e.Reason != "" {
				why += ", " + e.Reason
			}
			return fmt.Errorf("%w: certificate %d of the chain (serial %s) is %s in Google's attestation status list",
				ErrAttestationRevoked, i, s, why)
		}
	}
	return nil
}

// usableAt says whether this copy may be used at now.
//
// THE LIMIT OF THIS CHECK. now is the phone's own clock, and nothing here can
// tell it is wrong. A phone whose clock has been set back, and whose fetches are
// blocked, will take an old copy for a young one: a copy kept from a month ago
// looks a day old to a clock set back a month, so a certificate Google revoked
// since then is not refused. The list itself is unsigned and carries no time
// of its own to check the clock against. What this check does refuse is a copy
// whose fetch time is ahead of the clock, which no copy honestly fetched on
// this phone can have: it was written by a clock that has since gone back, or
// it was not written by this core.
func (l *statusList) usableAt(now time.Time) bool {
	return l != nil && !l.Fetched.After(now) && now.Sub(l.Fetched) < statusListUsableFor
}

// shrankFrom says whether fetched is so much shorter than held that it is not
// believed: held is still usable at now and fetched has fewer than
// statusListShrinkLimit of its entries.
func (fetched *statusList) shrankFrom(held *statusList, now time.Time) bool {
	return held.usableAt(now) && float64(len(fetched.Entries)) < statusListShrinkLimit*float64(len(held.Entries))
}

var (
	statusMu       sync.Mutex
	statusMem      *statusList
	statusMemDir   string
	statusLastTry  time.Time
	statusLastErr  error // why the last try failed, said again while the core is not trying
	statusDir      string
	statusDirMu    sync.RWMutex
	developmentLog sync.Once
)

// DeclareAttestationStatusDir says where the core keeps its copy of Google's
// list: its data directory. Called by mobilecore.StartServer. With none, the
// list is held in memory only, so a core that starts offline has none.
func DeclareAttestationStatusDir(dir string) {
	statusDirMu.Lock()
	statusDir = dir
	statusDirMu.Unlock()
}

func attestationStatusDir() string {
	statusDirMu.RLock()
	defer statusDirMu.RUnlock()
	return statusDir
}

func statusCachePath(dir string) string {
	return filepath.Join(dir, "secureenclave", statusCacheFile)
}

func readStatusCache(dir string) *statusList {
	if dir == "" {
		return nil
	}
	raw, err := os.ReadFile(statusCachePath(dir))
	if err != nil {
		return nil
	}
	var l statusList
	if json.Unmarshal(raw, &l) != nil || l.Entries == nil || l.Fetched.IsZero() {
		return nil
	}
	// Re-read through the same checks as a fetched list.
	body, _ := json.Marshal(struct {
		Entries map[string]statusEntry `json:"entries"`
	}{l.Entries})
	checked, err := parseStatusList(body, l.Fetched)
	if err != nil {
		return nil
	}
	return checked
}

func writeStatusCache(dir string, l *statusList) error {
	if dir == "" {
		return nil
	}
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	p := statusCachePath(dir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(p, data, 0o600)
}

// currentStatusList is the newest usable copy of Google's list, fetching it if
// the one held is older than a day and the last attempt was not just now.
func currentStatusList(now time.Time) (*statusList, error) {
	dir := attestationStatusDir()
	statusMu.Lock()
	defer statusMu.Unlock()

	if statusMemDir != dir {
		statusMem, statusMemDir, statusLastTry, statusLastErr = nil, dir, time.Time{}, nil
	}
	if statusMem.usableAt(now) && now.Sub(statusMem.Fetched) < statusListRefresh {
		return statusMem, nil
	}

	var fetchErr error
	if statusLastTry.IsZero() || now.Sub(statusLastTry) >= statusFetchBackoff || now.Before(statusLastTry) {
		statusLastTry = now
		ctx, cancel := context.WithTimeout(context.Background(), statusFetchTimeout)
		body, err := fetchStatusList(ctx)
		cancel()
		var l *statusList
		if err == nil {
			l, err = parseStatusList(body, now)
		}
		if err == nil {
			held := statusMem
			if d := readStatusCache(dir); d != nil && (held == nil || d.Fetched.After(held.Fetched)) {
				held = d
			}
			if held != nil && l.shrankFrom(held, now) {
				err = fmt.Errorf("the list fetched has %d entries, under half of the %d in the copy kept from %s, so it is not believed",
					len(l.Entries), len(held.Entries), held.Fetched.UTC().Format(time.RFC3339))
			}
		}
		if err == nil {
			if werr := writeStatusCache(dir, l); werr != nil {
				log.Printf("[keystore] could not keep Google's attestation status list in %s: %v", dir, werr)
			}
			statusMem, statusLastErr = l, nil
			return l, nil
		}
		statusLastErr = err
	}
	fetchErr = statusLastErr

	// Offline, or the last try failed: the newest copy that is still young enough.
	best := statusMem
	if d := readStatusCache(dir); d != nil && (best == nil || d.Fetched.After(best.Fetched)) {
		best = d
	}
	if best.usableAt(now) {
		statusMem = best
		return best, nil
	}
	why := "it could not be fetched"
	if fetchErr != nil {
		why = fmt.Sprintf("it could not be fetched (%v)", fetchErr)
	}
	if best != nil {
		return nil, fmt.Errorf("%w: %s, and the copy kept from %s is older than %d days",
			ErrNoStatusList, why, best.Fetched.UTC().Format(time.RFC3339), int(statusListUsableFor/(24*time.Hour)))
	}
	return nil, fmt.Errorf("%w: %s, and no copy has been kept", ErrNoStatusList, why)
}

// checkRevocation applies Google's list to a verified chain. A listed
// certificate refuses in every build. With no usable list a production build
// refuses and a development build lets the chain through, saying so in
// f.RevocationNote and once in the log.
func checkRevocation(f *AndroidKeyFacts, now time.Time) error {
	list, err := currentStatusList(now)
	if err != nil {
		if isDevBuild() {
			f.RevocationNote = "this chain was NOT checked against Google's revocation list: " + err.Error()
			developmentLog.Do(func() { log.Printf("[keystore] development build: %s", f.RevocationNote) })
			return nil
		}
		return fmt.Errorf("the key's attestation cannot be checked against Google's revocation list, "+
			"so a production build will not trust it: %w", err)
	}
	return list.check(f.Serials)
}
