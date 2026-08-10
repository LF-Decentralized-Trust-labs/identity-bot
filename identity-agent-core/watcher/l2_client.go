package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// L2Client queries commercial watcher /public/kel-digest endpoints.
type L2Client struct {
	HTTPClient *http.Client
}

func NewL2Client() *L2Client {
	return &L2Client{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
	return &out, time.Since(start), nil
}
