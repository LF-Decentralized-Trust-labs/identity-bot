package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/didwebs"
)

func (s *CoreServer) mountDidWebsPublicRoutes(r chi.Router) {
	r.Get("/{aid}/did.json", s.handleDidJSON)
	r.Get("/{aid}/kel", s.handleKEL)
	r.Get("/{aid}/keri.cesr", s.handleKeriCesr)
	r.Get("/{aid}/oobi", s.handleAidOobi)
	r.Get("/oobi/{aid}", s.handleAidOobi)
}

func (s *CoreServer) handleDidJSON(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	in, err := s.publisherInput(r, aid)
	if err != nil {
		if errors.Is(err, errNotPublishable) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := didwebs.BuildDidJSON(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/did+json; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=30")
	w.Header().Set("X-Keri-Keystate-Seq", strconv.Itoa(in.SequenceNumber))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *CoreServer) handleKEL(w http.ResponseWriter, r *http.Request) {
	s.serveCesrArtifact(w, r, true)
}

func (s *CoreServer) handleKeriCesr(w http.ResponseWriter, r *http.Request) {
	s.serveCesrArtifact(w, r, false)
}

func (s *CoreServer) serveCesrArtifact(w http.ResponseWriter, r *http.Request, canonical bool) {
	aid := chi.URLParam(r, "aid")
	in, err := s.publisherInput(r, aid)
	if err != nil {
		if errors.Is(err, errNotPublishable) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, complete, receiptHdr := didwebs.BuildCesrStream(in)
	w.Header().Set("Content-Type", "application/cesr")
	w.Header().Set("Cache-Control", "max-age=30")
	w.Header().Set("X-Keri-Keystate-Seq", strconv.Itoa(in.SequenceNumber))
	if complete {
		w.Header().Set("X-Keri-Cesr-Complete", "true")
	} else {
		w.Header().Set("X-Keri-Cesr-Complete", "false")
	}
	w.Header().Set("X-Keri-Cesr-Witness-Receipts", receiptHdr)
	if canonical {
		w.Header().Set("X-Keri-Cesr-Path-Role", "canonical")
	} else {
		w.Header().Set("X-Keri-Cesr-Path-Role", "spec-compat-alias")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *CoreServer) handleAidOobi(w http.ResponseWriter, r *http.Request) {
	s.handleOobiServe(w, r)
}

func (s *CoreServer) publisherInput(r *http.Request, aid string) (didwebs.PublishInput, error) {
	// Derive host from relay allocation / active tunnel public_url (not raw r.Host).
	// This ensures did.json for a re-randomized relay P-AID uses the stable public_url host.
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if s.EndpointService != nil {
		if u := s.EndpointService.CurrentURL(); u != "" {
			if idx := strings.Index(u, "://"); idx != -1 {
				u = u[idx+3:]
			}
			if idx := strings.Index(u, "/"); idx != -1 {
				u = u[:idx]
			}
			if idx := strings.Index(u, ":"); idx != -1 {
				u = u[:idx]
			}
			if u != "" {
				host = u
			}
		}
	}
	identity, _ := s.DataStore.GetIdentity()
	if identity != nil && identity.AID == aid {
		return didwebs.PublishInput{}, fmt.Errorf("%w: root aid", errNotPublishable)
	}
	pubKey := ""
	if c, _ := s.DataStore.GetContact(aid); c != nil && c.PublicKey != "" {
		pubKey = c.PublicKey
	}
	var kelEvents []map[string]interface{}
	seq := 0
	if s.KeriDriver != nil {
		if kel, err := s.KeriDriver.GetKel(aid); err == nil {
			kelEvents = kel.KEL
			seq = kel.SequenceNumber
		}
	}
	if pubKey == "" && identity != nil {
		pubKey = identity.PublicKey
	}
	if pubKey == "" {
		return didwebs.PublishInput{}, fmt.Errorf("no public key for aid %s", aid)
	}
	// Real witness receipt counts (plumbed; default conservative until per-AID tracking is wired in witness service).
	receipts, threshold := 0, 5
	if s.WitnessService != nil {
		// TODO(joint M35): query actual receipt count / threshold for this aid from witness state.
		threshold = 5
	}
	return didwebs.PublishInput{
		AID: aid, Host: host, PublicKeyB64: pubKey,
		SequenceNumber: seq, KELEvents: kelEvents,
		WitnessReceipts: receipts, WitnessThreshold: threshold,
	}, nil
}

var errNotPublishable = errors.New("not publishable")