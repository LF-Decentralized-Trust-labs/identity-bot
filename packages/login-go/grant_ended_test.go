package login

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type grantEndedVectors struct {
	PublicHex string         `json:"public_hex"`
	Now       string         `json:"now"`
	StaleNow  string         `json:"stale_now"`
	Notice    map[string]any `json:"notice"`
	Statement string         `json:"statement"`
	Refusals  []struct {
		Name, Change, Value string
	} `json:"refusals"`
	RefusedBodies []struct {
		Name, Suffix, Body string
	} `json:"refused_bodies"`
}

func readGrantEnded(t *testing.T) (grantEndedVectors, ed25519.PublicKey, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("../login-web/test-vectors/grant-ended.json")
	if err != nil {
		t.Fatal(err)
	}
	var v grantEndedVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(v.PublicHex)
	now, _ := time.Parse(time.RFC3339, v.Now)
	return v, pub, now
}

func body(m map[string]any) []byte { b, _ := json.Marshal(m); return b }

func TestAGrantEndedNoticeTheCoreSignedChecks(t *testing.T) {
	v, pub, now := readGrantEnded(t)
	n := v.Notice
	if got := string(GrantEndedStatement(n["asset"].(string), n["key"].(string), n["person"].(string), n["issued"].(string))); got != v.Statement {
		t.Fatalf("statement\n got %q\nwant %q", got, v.Statement)
	}
	g, err := VerifyGrantEnded(body(n), n["asset"].(string), pub, now)
	if err != nil || g.Key != n["key"] || g.Person != n["person"] {
		t.Fatalf("the vector's notice: %+v %v", g, err)
	}
}

func TestANoticeThatChangedAfterSigningOrIsForAnotherAppOrIsStaleIsRefused(t *testing.T) {
	v, pub, now := readGrantEnded(t)
	asset := v.Notice["asset"].(string)
	for _, r := range v.Refusals {
		n := map[string]any{}
		for k, x := range v.Notice {
			n[k] = x
		}
		if r.Change == "v" {
			n["v"] = 2
		} else {
			n[r.Change] = r.Value
		}
		if _, err := VerifyGrantEnded(body(n), asset, pub, now); err == nil {
			t.Errorf("%s was taken", r.Name)
		}
	}
	for _, r := range v.RefusedBodies {
		b := r.Body
		if b == "" {
			b = string(body(v.Notice)) + r.Suffix
		}
		if _, err := VerifyGrantEnded([]byte(b), asset, pub, now); err == nil {
			t.Errorf("%s was taken", r.Name)
		}
	}
	stale, _ := time.Parse(time.RFC3339, v.StaleNow)
	if _, err := VerifyGrantEnded(body(v.Notice), asset, pub, stale); err == nil {
		t.Error("a notice outside the window was taken")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyGrantEnded(body(v.Notice), asset, other, now); err == nil {
		t.Error("a notice was taken against another key")
	}
	extra := map[string]any{"extra": 1}
	for k, x := range v.Notice {
		extra[k] = x
	}
	if _, err := VerifyGrantEnded(body(extra), asset, pub, now); err == nil {
		t.Error("a notice with a field it does not define was taken")
	}
}

func TestTheHandlerEndsTheGrantOnlyForANoticeThatChecks(t *testing.T) {
	v, pub, now := readGrantEnded(t)
	asset := v.Notice["asset"].(string)
	var ended []GrantEnded
	var cutoffs []time.Time
	h := GrantEndedHandler(asset, func(context.Context) (ed25519.PublicKey, error) { return pub, nil },
		func(_ context.Context, g GrantEnded, begunBy time.Time) (int, error) {
			ended, cutoffs = append(ended, g), append(cutoffs, begunBy)
			return 1, nil
		},
		func() time.Time { return now })
	post := func(b string) int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, GrantEndedPath, strings.NewReader(b)))
		return rr.Code
	}
	bad := map[string]any{}
	for k, x := range v.Notice {
		bad[k] = x
	}
	bad["key"] = strings.Repeat("j", 43)
	if code := post(string(body(bad))); code != http.StatusForbidden || len(ended) != 0 {
		t.Fatalf("a forged notice: %d, ended %d", code, len(ended))
	}
	if code := post(string(body(v.Notice))); code != http.StatusOK || len(ended) != 1 || ended[0].Person != v.Notice["person"] {
		t.Fatalf("a good notice: %d, %+v", code, ended)
	}
	// The back end is handed the notice's time as the cutoff: sessions begun after it stay.
	if want, _ := time.Parse("2006-01-02T15:04:05Z", v.Notice["issued"].(string)); !cutoffs[0].Equal(want) {
		t.Fatalf("the cutoff given to end is %s, want the notice's time %s", cutoffs[0], want)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, GrantEndedPath, nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a GET: %d", rr.Code)
	}
}
