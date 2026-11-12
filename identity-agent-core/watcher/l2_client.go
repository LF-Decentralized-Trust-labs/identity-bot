package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/witness"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultL2DigestURL is the standing watcher this agent asks when it has no
// peers of its own.
//
// Numbered, like the witnesses. There is one operator today and there are
// expected to be more, and an unnumbered name would have to be re-pointed to
// add a second rather than simply joined by one. It also previously named a
// host with no DNS at all, so every L2 query failed and was recorded as the
// service being unavailable — which reads as an outage rather than as a
// mistake in a constant.
const DefaultL2DigestURL = "https://watcher1.grapeid.org/public/kel-digest"

// L2Client queries commercial watcher /public/kel-digest endpoints. Some of
// the addresses it is given are hints a peer's introduction carried, so its
// client refuses an internal address (the one dialled), follows no redirect and
// uses no proxy, and is never allowed a local address.
//
// An answer is used only if a watcher this agent trusts signed it. TrustedSigners
// names those watchers; with none, no answer is ever accepted, so a client that
// was not told whom to trust fails closed into "unavailable".
type L2Client struct {
	HTTPClient *http.Client
	// TrustedSigners returns the non-transferable identifiers whose signature
	// on a digest answer is accepted.
	TrustedSigners func() []string
}

func NewL2Client() *L2Client {
	return &L2Client{HTTPClient: witness.GuardedClient(5*time.Second, false)}
}

func (c *L2Client) QueryDigest(ctx context.Context, baseURL, aid string, seq int) (*DigestResponse, time.Duration, error) {
	start := time.Now()
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, 0, err
	}
	if !strings.HasSuffix(u.Path, "/public/kel-digest") {
		u.Path = strings.TrimRight(u.Path, "/") + "/public/kel-digest"
	}
	q := u.Query()
	q.Set("aid", aid)
	q.Set("seq", fmt.Sprintf("%d", seq))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer resp.Body.Close()
	body, err := boundedread.All(resp.Body, boundedread.Document)
	if err != nil {
		return nil, time.Since(start), err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, time.Since(start), fmt.Errorf("L2 query %s: HTTP %d", u.String(), resp.StatusCode)
	}
	var out DigestResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, time.Since(start), err
	}
	if err := c.verifyAnswer(&out, aid, seq); err != nil {
		// Unavailable, never evidence: an answer nobody can prove a trusted
		// watcher gave is not allowed to say anything about an identity.
		return nil, time.Since(start), fmt.Errorf("L2 answer from %s not accepted: %w", u.Host, err)
	}
	return &out, time.Since(start), nil
}

// verifyAnswer checks that the answer is for the question asked and was signed,
// over the statement both sides build, by a watcher this client trusts. The
// signer is a non-transferable identifier, so it is itself the key.
func (c *L2Client) verifyAnswer(r *DigestResponse, aid string, seq int) error {
	if r.AID != aid || r.SequenceNumber != seq {
		return fmt.Errorf("it answers for %s at %d, not %s at %d", r.AID, r.SequenceNumber, aid, seq)
	}
	if r.SignedBy == "" || r.Signature == "" {
		return fmt.Errorf("it is not signed")
	}
	trusted := false
	if c.TrustedSigners != nil {
		// Compared by key, so one watcher is one watcher however it is spelt.
		want, ok := drivers.WitnessKey(r.SignedBy)
		for _, t := range c.TrustedSigners() {
			if k, kok := drivers.WitnessKey(t); ok && kok && k == want {
				trusted = true
			}
		}
	}
	if !trusted {
		return fmt.Errorf("%s is not a watcher this agent trusts", r.SignedBy)
	}
	stmt, err := witnessproto.DigestStatementWithRival(r.AID, r.SequenceNumber, r.Digest, r.FirstSeenAt, r.ObservedSince, r.RivalAtOrBelow)
	if err != nil {
		return err
	}
	return drivers.VerifyReceipt(r.SignedBy, stmt, r.Signature)
}

// logURL is where a watcher whose digest address is digestURL serves the key log
// it holds for aid.
func logURL(digestURL, aid string) (string, error) {
	u, err := url.Parse(strings.TrimRight(digestURL, "/"))
	if err != nil {
		return "", err
	}
	p := strings.TrimSuffix(u.Path, "/public/kel-digest")
	p = strings.TrimSuffix(p, "/api")
	u.Path = strings.TrimRight(p, "/") + "/witness/kel/" + url.PathEscape(aid)
	u.RawQuery = ""
	return u.String(), nil
}

// FetchLog asks a watcher for the key log it holds for aid, with the controller
// signatures and any rival events it kept. Nothing in the answer is believed:
// it is judged by judgeWatcherLog, which verifies every signature itself, so
// the answer need not be signed and a watcher that cannot be reached or hands
// back something unreadable is simply one that has shown nothing.
func (c *L2Client) FetchLog(ctx context.Context, digestURL, aid string) (*WatcherLog, error) {
	target, err := logURL(digestURL, aid)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key log from %s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	body, err := boundedread.All(resp.Body, boundedread.Document)
	if err != nil {
		return nil, err
	}
	var out struct {
		KEL         []map[string]interface{} `json:"kel"`
		Conflicting []map[string]interface{} `json:"conflicting"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	var log WatcherLog
	if len(out.KEL) > 0 {
		if log.Messages, err = drivers.SignedMessagesFromRecords(out.KEL); err != nil {
			// Its log cannot be read as signed events: it has shown nothing.
			return nil, fmt.Errorf("key log from %s: %w", req.URL.Host, err)
		}
		log.Records = out.KEL
	}
	for _, rec := range out.Conflicting {
		if m, err := drivers.SignedMessagesFromRecords([]map[string]interface{}{rec}); err == nil {
			log.Rival = append(log.Rival, m...)
		}
	}
	return &log, nil
}
