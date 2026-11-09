package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// The sequences are data, shared with the TypeScript verifier
// (packages/login-verify/src/a-sign-in-is-spent-only-by-an-accepted-answer.test.mjs),
// so both are held to the same rule: only an accepted answer spends a sign-in.
type spendingSequences struct {
	Sequences []struct {
		Name  string `json:"name"`
		Steps []struct {
			Answer  string `json:"answer"`
			Outcome string `json:"outcome"`
			After   string `json:"after"`
		} `json:"steps"`
	} `json:"sequences"`
}

func loadSpendingSequences(t *testing.T) spendingSequences {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packages", "login-verify", "test-vectors", "spending-sequences.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v spendingSequences
	if err := json.Unmarshal(b, &v); err != nil || len(v.Sequences) == 0 {
		t.Fatalf("spending sequences unreadable: %v", err)
	}
	return v
}

func postAnswer(t *testing.T, w *aWebsiteWorld, session string, raw []byte) int {
	t.Helper()
	resp, err := http.Post(w.srv.URL+"/api/login/callback?session="+session, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestASignInIsSpentOnlyByAnAcceptedAnswer(t *testing.T) {
	for _, seq := range loadSpendingSequences(t).Sequences {
		t.Run(seq.Name, func(t *testing.T) {
			w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
			h := aPersonsIdentityAgent(t)
			req := aBrowserKeyChallenge(t, w, aBrowserKey)
			bundle := w.org.challenges[req.SessionToken]
			rel, err := h.GetOrCreateRelationship(bundle.SiteAID, &bundle)
			if err != nil {
				t.Fatal(err)
			}
			build := func(c login.ChallengeBundle) login.Assertion {
				a, err := h.BuildAssertion(rel, &c, nil)
				if err != nil {
					t.Fatal(err)
				}
				return *a
			}
			answer := func(kind string) []byte {
				var a login.Assertion
				switch kind {
				case "genuine":
					a = build(bundle)
				case "tampered-signature":
					a = build(bundle)
					a.Sig = a.Sig[:len(a.Sig)-4] + "AAAA"
				case "wrong-nonce":
					c := bundle
					c.Nonce = "a-nonce-this-challenge-never-issued"
					a = build(c)
				case "wrong-audience":
					c := bundle
					c.Audience = "https://elsewhere.example"
					a = build(c)
				default:
					t.Fatalf("unknown answer %q", kind)
				}
				raw, _ := json.Marshal(a)
				return raw
			}
			for i, step := range seq.Steps {
				code := postAnswer(t, w, req.SessionToken, answer(step.Answer))
				want := map[string]func(int) bool{
					"accepted":      func(c int) bool { return c == http.StatusOK },
					"refused":       func(c int) bool { return c == http.StatusUnauthorized || c == http.StatusForbidden },
					"already-spent": func(c int) bool { return c == http.StatusConflict },
				}[step.Outcome]
				if want == nil || !want(code) {
					t.Fatalf("step %d (%s): answered %d, want %s", i+1, step.Answer, code, step.Outcome)
				}
				status := theStatus(w, req.SessionToken)
				if (step.After == "spent") != (status != "pending") {
					t.Fatalf("step %d (%s): the sign-in is %v, want it %s", i+1, step.Answer, status, step.After)
				}
			}
		})
	}
}

// Two accepted answers arriving together: one spends the sign-in and the other
// is told it is spent, rather than both being taken.
func TestTwoAcceptedAnswersAtOnceSpendTheSignInOnce(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	h := aPersonsIdentityAgent(t)
	req := aBrowserKeyChallenge(t, w, aBrowserKey)
	bundle := w.org.challenges[req.SessionToken]
	rel, err := h.GetOrCreateRelationship(bundle.SiteAID, &bundle)
	if err != nil {
		t.Fatal(err)
	}
	var raws [][]byte
	for i := 0; i < 8; i++ {
		a, err := h.BuildAssertion(rel, &bundle, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(a)
		raws = append(raws, raw)
	}
	codes := make([]int, len(raws))
	var wg sync.WaitGroup
	for i := range raws {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i] = postAnswer(t, w, req.SessionToken, raws[i]) }(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		} else if c != http.StatusConflict {
			t.Fatalf("answers %v", codes)
		}
	}
	if ok != 1 {
		t.Fatalf("%d answers were accepted, want 1: %v", ok, codes)
	}
}

// A refused answer is kept on the open sign-in with its reason, for the
// organisation, and the person's own answer is still taken afterwards.
func TestARefusedAnswerIsRecordedOnTheOpenSignIn(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	h := aPersonsIdentityAgent(t)
	req := aBrowserKeyChallenge(t, w, aBrowserKey)
	bundle := w.org.challenges[req.SessionToken]
	rel, _ := h.GetOrCreateRelationship(bundle.SiteAID, &bundle)
	forged := bundle
	forged.BrowserKey = anotherBrowserKey
	a, _ := h.BuildAssertion(rel, &forged, nil)
	raw, _ := json.Marshal(a)
	if code := postAnswer(t, w, req.SessionToken, raw); code != http.StatusUnauthorized {
		t.Fatalf("answered %d", code)
	}
	st := w.org.challengeStatusOf(req.SessionToken)
	if st["status"] != "pending" || st["refusals"] != 1 || st["last_refusal"] == "" || st["last_refusal"] == nil {
		t.Fatalf("the refusal was not recorded on an open sign-in: %v", st)
	}
	if _, err := h.Approve(req); err != nil {
		t.Fatalf("the person's own answer was refused after a forged one: %v", err)
	}
}
