package remote

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type gcsBackend struct {
	bucket string
	prefix string
	access string
	secret string
	client *http.Client
}

func NewGCSBackend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	if dest.Bucket == "" {
		return nil, fmt.Errorf("gcs destination requires cloud_bucket")
	}
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return nil, fmt.Errorf("gcs destination requires HMAC access_key and secret_key")
	}
	return &gcsBackend{
		bucket: dest.Bucket,
		prefix: strings.Trim(dest.Prefix, "/"),
		access: creds.AccessKey,
		secret: creds.SecretKey,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (b *gcsBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	u := b.objectURL(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	b.sign(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gcs push %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (b *gcsBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	u := b.objectURL(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	b.sign(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gcs pull %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (b *gcsBackend) List(ctx context.Context, prefix string) ([]string, error) {
	listPrefix := b.prefix
	if prefix != "" {
		listPrefix = strings.Trim(prefix, "/")
	}
	u := fmt.Sprintf("https://storage.googleapis.com/%s?prefix=%s", b.bucket, url.QueryEscape(listPrefix))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	b.sign(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gcs list %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseS3ListKeys(body), nil
}

func (b *gcsBackend) objectURL(objectKey string) string {
	key := objectKey
	if b.prefix != "" {
		key = strings.Trim(b.prefix, "/") + "/" + strings.TrimLeft(objectKey, "/")
	}
	return fmt.Sprintf("https://storage.googleapis.com/%s/%s", b.bucket, escapeGCSPath(key))
}

func escapeGCSPath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func (b *gcsBackend) sign(req *http.Request) {
	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	req.Header.Set("Date", date)
	canonical := req.Method + "\n\n" + req.Header.Get("Content-Type") + "\n" + date + "\n" + req.URL.Path
	mac := hmac.New(sha1.New, []byte(b.secret))
	mac.Write([]byte(canonical))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set("Authorization", "GOOG1 "+b.access+":"+sig)
}
