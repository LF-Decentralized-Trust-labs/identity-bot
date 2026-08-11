package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

type webdavBackend struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

func NewWebDAVBackend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	base := strings.TrimRight(dest.RemoteURL, "/")
	if base == "" {
		base = strings.TrimRight(dest.Endpoint, "/")
	}
	if base == "" {
		return nil, fmt.Errorf("webdav destination requires remote_url or cloud_endpoint")
	}
	return &webdavBackend{
		baseURL:  base,
		username: creds.Username,
		password: creds.Password,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (b *webdavBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	u := b.baseURL + "/" + strings.TrimLeft(objectKey, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if b.username != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webdav push %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (b *webdavBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	u := b.baseURL + "/" + strings.TrimLeft(objectKey, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if b.username != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("webdav pull %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (b *webdavBackend) List(ctx context.Context, prefix string) ([]string, error) {
	u := b.baseURL
	if prefix != "" {
		u = path.Join(b.baseURL, prefix)
	}
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Depth", "1")
	if b.username != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("webdav list %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseWebDAVHrefs(string(body)), nil
}

func parseWebDAVHrefs(xml string) []string {
	var keys []string
	for {
		i := strings.Index(xml, "<href>")
		if i < 0 {
			break
		}
		xml = xml[i+6:]
		j := strings.Index(xml, "</href>")
		if j < 0 {
			break
		}
		href := strings.TrimSpace(xml[:j])
		if strings.HasSuffix(href, ".iab") {
			keys = append(keys, strings.TrimPrefix(href, "/"))
		}
		xml = xml[j+7:]
	}
	return keys
}
