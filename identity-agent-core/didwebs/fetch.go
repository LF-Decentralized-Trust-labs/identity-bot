package didwebs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const headerKeystateSeq = "X-Keri-Keystate-Seq"
const headerCesrComplete = "X-Keri-Cesr-Complete"

type fetchResult struct {
	body       []byte
	status     int
	keystateSeq int
	cesrComplete bool
}

// Resolver fetches and validates did:webs artifacts.
type Resolver struct {
	HTTPClient *http.Client
	Replay     KELReplayBackend
}

func NewResolver(replay KELReplayBackend) *Resolver {
	return &Resolver{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Replay:     replay,
	}
}

func (r *Resolver) Resolve(ctx context.Context, urls *ArtifactURLs) (*ResolvedDID, FetchStatus, error) {
	if urls == nil {
		return nil, FetchError, fmt.Errorf("nil urls")
	}
	didRes, err := r.fetch(ctx, urls.DidJSONURL)
	if err != nil {
		return nil, FetchError, err
	}
	cesrRes, cesrErr := r.fetch(ctx, urls.CesrURL)
	if didRes.status == http.StatusNotFound && (cesrErr != nil || cesrRes.status == http.StatusNotFound) {
		return &ResolvedDID{DID: urls.DID, AID: urls.AID, Host: urls.Host}, FetchNotFound, nil
	}
	if didRes.status != http.StatusOK {
		return &ResolvedDID{AID: urls.AID}, FetchPartial, nil
	}
	if cesrErr != nil || cesrRes.status != http.StatusOK {
		return &ResolvedDID{AID: urls.AID}, FetchPartial, nil
	}
	if didRes.keystateSeq != cesrRes.keystateSeq && didRes.keystateSeq >= 0 && cesrRes.keystateSeq >= 0 {
		return &ResolvedDID{
			DID: urls.DID, AID: urls.AID,
			DidKeystateSeq: didRes.keystateSeq, CesrKeystateSeq: cesrRes.keystateSeq,
		}, FetchSeqMismatch, nil
	}

	var didDoc map[string]interface{}
	if err := json.Unmarshal(didRes.body, &didDoc); err != nil {
		return nil, FetchError, err
	}
	events, err := parseKELEvents(cesrRes.body)
	if err != nil {
		// OOBI fallback — kel as JSON
		events, err = r.fetchOOBIKEL(ctx, urls.OobiURL)
		if err != nil || len(events) == 0 {
			return &ResolvedDID{AID: urls.AID, DidJSON: didDoc}, FetchPartial, nil
		}
	}

	out := &ResolvedDID{
		DID: urls.DID, AID: urls.AID, Host: urls.Host,
		DidJSON: didDoc, Events: events,
		DidKeystateSeq: didRes.keystateSeq, CesrKeystateSeq: cesrRes.keystateSeq,
		CesrComplete: cesrRes.cesrComplete, FetchedAt: time.Now().UTC(),
	}
	if r.Replay != nil && len(events) > 0 {
		ok, pub, errs, _ := r.Replay.ValidateKEL(ctx, urls.AID, events)
		out.ReplayVerified = ok
		out.ReplayErrors = errs
		out.CurrentPublicKey = pub
	}
	if id, ok := didDoc["id"].(string); ok && id != "" && id != urls.DID {
		out.ReplayVerified = false
		out.ReplayErrors = append(out.ReplayErrors, "did.json id mismatch")
	}
	return out, FetchOK, nil
}

func (r *Resolver) fetch(ctx context.Context, u string) (*fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	seq := parseSeqHeader(resp.Header.Get(headerKeystateSeq))
	complete := resp.Header.Get(headerCesrComplete) != "false"
	return &fetchResult{body: body, status: resp.StatusCode, keystateSeq: seq, cesrComplete: complete}, nil
}

func (r *Resolver) fetchOOBIKEL(ctx context.Context, oobiURL string) ([]map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oobiURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oobi %d", resp.StatusCode)
	}
	var data struct {
		KEL []map[string]interface{} `json:"kel"`
		AID string                   `json:"aid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data.KEL, nil
}

func parseKELEvents(body []byte) ([]map[string]interface{}, error) {
	trim := strings.TrimSpace(string(body))
	if trim == "" {
		return nil, fmt.Errorf("empty cesr")
	}
	if trim[0] == '[' {
		var events []map[string]interface{}
		if err := json.Unmarshal(body, &events); err != nil {
			return nil, err
		}
		return events, nil
	}
	// BLOCKED: raw CESR byte stream decode requires keripy cesr-stream endpoint (M35 IF7).
	return nil, fmt.Errorf("binary cesr not supported without driver cesr-stream")
}

func parseSeqHeader(v string) int {
	if v == "" {
		return -1
	}
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}