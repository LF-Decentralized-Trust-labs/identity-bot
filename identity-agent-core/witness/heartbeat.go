package witness

import (
	"context"
	"io"
	"net/http"
	"time"
)

// StartHeartbeatLoop runs C8 health probes every HeartbeatInterval.
func StartHeartbeatLoop(s *Service, stop <-chan struct{}) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.runHeartbeatPass(context.Background())
		}
	}
}

func (s *Service) runHeartbeatPass(ctx context.Context) {
	contacts, err := s.Contacts.GetContacts()
	if err != nil {
		return
	}
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: HeartbeatTimeout}
	}
	for _, c := range contacts {
		if !c.IsWitness || c.OobiURL == "" {
			continue
		}
		url := healthURL(c.OobiURL)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			s.RecordHeartbeatResult(c.AID, false)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			s.RecordHeartbeatResult(c.AID, false)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		s.RecordHeartbeatResult(c.AID, resp.StatusCode == http.StatusOK)
	}
}

// healthURL is where an Identity Agent asks a witness whether it is alive.
//
// Derived from witnessBase rather than repeating its trimming, which is how
// the two drifted: this copy and that one both stripped only "/public/oobi/",
// a path our witnesses never publish, so the probe was appended to a full
// endpoint path and 404'd every time. Each failure counted towards
// OfflineFailureThreshold, so healthy witnesses were marching towards being
// written off — and being written off means looking for a replacement, which
// means a key rotation.
//
// The /api prefix matches what an Identity Agent serves for its own witness
// routes, which is the convention a witness is addressed by. A witness service
// is expected to answer health there as well as at /health.
func healthURL(oobi string) string {
	return witnessBase(oobi) + "/api/health"
}
