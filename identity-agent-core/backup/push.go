package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PushRequest is the paired-device backup push protocol (SEAM-19).
type PushRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	IdentityAID     string `json:"identity_aid,omitempty"`
	ArchiveB64      string `json:"archive_b64"`
	ArchiveSize     int    `json:"archive_size"`
	SentAt          string `json:"sent_at"`
}

// PushResponse is the receipt from a backup-only device.
type PushResponse struct {
	Received   bool   `json:"received"`
	StoredPath string `json:"stored_path,omitempty"`
	Message    string `json:"message,omitempty"`
}

// PairedPusher sends encrypted archives to paired agents.
type PairedPusher struct {
	Client *http.Client
}

func NewPairedPusher() *PairedPusher {
	return &PairedPusher{
		Client: &http.Client{Timeout: 120 * time.Second},
	}
}

// Push transmits ciphertext to POST {pairedURL}/api/backup/receive.
func (p *PairedPusher) Push(pairedURL string, archive []byte) error {
	base := trimSlash(pairedURL)
	reqBody := PushRequest{
		ProtocolVersion: 1,
		ArchiveB64:      EncodeB64(archive),
		ArchiveSize:     len(archive),
		SentAt:          time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	url := base + "/api/backup/receive"
	resp, err := p.Client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("push to %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push failed %d: %s", resp.StatusCode, string(b))
	}
	var receipt PushResponse
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		return err
	}
	if !receipt.Received {
		return fmt.Errorf("destination declined: %s", receipt.Message)
	}
	return nil
}

func trimSlash(u string) string {
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	return u
}