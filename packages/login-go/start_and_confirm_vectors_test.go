package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The same file the TypeScript start and confirm are held to.
const vectorsPath = "../login-web/test-vectors/start-and-confirm.json"

type response struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Text   string          `json:"text"`
}

type vectors struct {
	Start []struct {
		Name  string `json:"name"`
		Input struct {
			AgentURL           string   `json:"agent_url"`
			AssetID            string   `json:"asset_id"`
			Audience           string   `json:"audience"`
			RequestDisclosures []string `json:"request_disclosures"`
			BrowserKey         string   `json:"browser_key"`
			FrontEnd           string   `json:"front_end"`
		} `json:"input"`
		Request struct {
			Method string         `json:"method"`
			URL    string         `json:"url"`
			Body   map[string]any `json:"body"`
		} `json:"request"`
		Response response `json:"response"`
		Expect   struct {
			SessionToken    string `json:"session_token"`
			PointerURL      string `json:"pointer_url"`
			CollectorSecret string `json:"collector_secret"`
			ErrorContains   string `json:"error_contains"`
		} `json:"expect"`
	} `json:"start"`
	Confirm []struct {
		Name  string `json:"name"`
		Input struct {
			AgentURL        string `json:"agent_url"`
			AssetID         string `json:"asset_id"`
			SessionToken    string `json:"session_token"`
			CollectorSecret string `json:"collector_secret"`
		} `json:"input"`
		Request struct {
			URL             string `json:"url"`
			CollectorSecret string `json:"collector_secret"`
		} `json:"request"`
		Response response `json:"response"`
		Expect   struct {
			State         string            `json:"state"`
			PairwiseAID   string            `json:"pairwise_aid"`
			Disclosures   map[string]any    `json:"disclosures"`
			RawMember     map[string]string `json:"member_info"`
			BrowserKey    string            `json:"browser_key"`
			FrontEnd      string            `json:"front_end"`
			Reason        string            `json:"reason"`
			ErrorContains string            `json:"error_contains"`
		} `json:"expect"`
	} `json:"confirm"`
	Spending struct {
		Input struct {
			AgentURL        string `json:"agent_url"`
			AssetID         string `json:"asset_id"`
			CollectorSecret string `json:"collector_secret"`
		} `json:"input"`
		Steps []struct {
			SessionToken string         `json:"session_token"`
			Response     map[string]any `json:"response"`
			Expect       struct {
				State         string `json:"state"`
				ErrorContains string `json:"error_contains"`
			} `json:"expect"`
		} `json:"steps"`
	} `json:"spending"`
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func answer(r response) *http.Response {
	text := r.Text
	if text == "" {
		text = string(r.Body)
	}
	return &http.Response{StatusCode: r.Status, Body: io.NopCloser(strings.NewReader(text)), Header: http.Header{}}
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestStartMatchesTheSharedVectors(t *testing.T) {
	v := load(t)
	if len(v.Start) == 0 {
		t.Fatal("no start vectors were read")
	}
	for _, c := range v.Start {
		var gotURL, gotMethod string
		var gotBody map[string]any
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			gotURL, gotMethod = r.URL.String(), r.Method
			b, _ := io.ReadAll(r.Body)
			_ = json.NewDecoder(bytes.NewReader(b)).Decode(&gotBody)
			return answer(c.Response), nil
		})}
		i := c.Input
		got, err := StartSession(context.Background(), StartOptions{AgentURL: i.AgentURL, AssetID: i.AssetID, Audience: i.Audience,
			RequestDisclosures: i.RequestDisclosures, BrowserKey: i.BrowserKey, FrontEnd: i.FrontEnd, Client: client})
		if c.Expect.ErrorContains != "" {
			if err == nil || !strings.Contains(err.Error(), c.Expect.ErrorContains) {
				t.Errorf("%s: error %v, want it to contain %q", c.Name, err, c.Expect.ErrorContains)
			}
		} else if err != nil {
			t.Errorf("%s: %v", c.Name, err)
		} else if got != (Started{SessionToken: c.Expect.SessionToken, PointerUrl: c.Expect.PointerURL, CollectorSecret: c.Expect.CollectorSecret}) {
			t.Errorf("%s: got %+v", c.Name, got)
		}
		if gotURL != c.Request.URL || gotMethod != c.Request.Method || !reflect.DeepEqual(gotBody, c.Request.Body) {
			t.Errorf("%s: sent %s %s %v, want %s %s %v", c.Name, gotMethod, gotURL, gotBody, c.Request.Method, c.Request.URL, c.Request.Body)
		}
	}
}

func TestConfirmMatchesTheSharedVectors(t *testing.T) {
	v := load(t)
	if len(v.Confirm) == 0 {
		t.Fatal("no confirm vectors were read")
	}
	for _, c := range v.Confirm {
		var gotURL, gotSecret string
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			gotURL, gotSecret = r.URL.String(), r.Header.Get("X-Collector-Secret")
			return answer(c.Response), nil
		})}
		i := c.Input
		got, err := ConfirmSession(context.Background(), ConfirmOptions{AgentURL: i.AgentURL, AssetID: i.AssetID, SessionToken: i.SessionToken, CollectorSecret: i.CollectorSecret, Client: client})
		if c.Expect.ErrorContains != "" {
			if err == nil || !strings.Contains(err.Error(), c.Expect.ErrorContains) {
				t.Errorf("%s: error %v, want it to contain %q", c.Name, err, c.Expect.ErrorContains)
			}
		} else if err != nil {
			t.Errorf("%s: %v", c.Name, err)
		} else {
			want := Confirmed{State: State(c.Expect.State), PairwiseAID: c.Expect.PairwiseAID, Disclosures: c.Expect.Disclosures, BrowserKey: c.Expect.BrowserKey, FrontEnd: c.Expect.FrontEnd, Reason: c.Expect.Reason}
			if m := c.Expect.RawMember; m != nil {
				want.MemberInfo = &MemberInfo{Role: m["role"], DisplayName: m["display_name"]}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got %+v, want %+v", c.Name, got, want)
			}
		}
		if gotURL != c.Request.URL || gotSecret != c.Request.CollectorSecret {
			t.Errorf("%s: asked %s with secret %q, want %s with %q", c.Name, gotURL, gotSecret, c.Request.URL, c.Request.CollectorSecret)
		}
	}
}

func TestASpentSignInIsRefusedTheSecondTime(t *testing.T) {
	v := load(t)
	s := v.Spending
	if len(s.Steps) == 0 {
		t.Fatal("no spending steps were read")
	}
	store := &InMemorySpent{}
	for n, step := range s.Steps {
		raw, _ := json.Marshal(step.Response)
		client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return answer(response{Status: 200, Body: raw}), nil
		})}
		got, err := ConfirmSession(context.Background(), ConfirmOptions{AgentURL: s.Input.AgentURL, AssetID: s.Input.AssetID,
			SessionToken: step.SessionToken, CollectorSecret: s.Input.CollectorSecret, Client: client, Spent: store})
		switch {
		case step.Expect.ErrorContains != "":
			if !errors.Is(err, ErrAlreadyUsed) || !strings.Contains(err.Error(), step.Expect.ErrorContains) {
				t.Errorf("step %d: error %v", n, err)
			}
		case err != nil || string(got.State) != step.Expect.State:
			t.Errorf("step %d: got %+v, %v; want %s", n, got, err, step.Expect.State)
		}
	}
}

func TestAStoreForgetsASignInAfterItsWindow(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	s := &InMemorySpent{Now: func() time.Time { return now }}
	if ok, _ := s.Claim("k", now.Add(time.Minute)); !ok {
		t.Fatal("first claim refused")
	}
	if ok, _ := s.Claim("k", now.Add(time.Minute)); ok {
		t.Fatal("second claim allowed")
	}
	now = now.Add(2 * time.Minute)
	if ok, _ := s.Claim("k", now.Add(time.Minute)); !ok {
		t.Fatal("a claim past its window was still remembered")
	}
}

func TestTheSpentWindowIsCarriedOnTheClaim(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	var until []time.Time
	rec := recorder(func(_ string, k time.Time) { until = append(until, k) })
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return answer(response{Status: 200, Body: json.RawMessage(`{"state":"verified","app_session_token":"EP"}`)}), nil
	})}
	o := ConfirmOptions{AgentURL: "https://ia.example", AssetID: "a", SessionToken: "t", Client: client, Spent: rec, Now: func() time.Time { return now }}
	if _, err := ConfirmSession(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	o.SpentFor = time.Minute
	if _, err := ConfirmSession(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !until[0].Equal(now.Add(time.Hour)) || !until[1].Equal(now.Add(time.Minute)) {
		t.Errorf("windows %v: want an hour by default, then a minute", until)
	}
}

type recorder func(string, time.Time)

func (r recorder) Claim(k string, u time.Time) (bool, error) { r(k, u); return true, nil }
