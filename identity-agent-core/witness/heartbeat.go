package witness

import (
	"context"
	"io"
	"net/http"
	"strings"
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

func healthURL(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/") + "/api/health"
}
