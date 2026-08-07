package remote

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type azureBackend struct {
	account   string
	container string
	prefix    string
	key       string
	client    *http.Client
}

func NewAzureBackend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	account := creds.AccountName
	if account == "" {
		account = dest.Bucket
	}
	if account == "" {
		return nil, fmt.Errorf("azure destination requires account_name or cloud_bucket")
	}
	container := dest.Prefix
	if container == "" {
		return nil, fmt.Errorf("azure destination requires cloud_prefix as container name")
	}
	if creds.AccessKey == "" {
		return nil, fmt.Errorf("azure destination requires access_key (shared key)")
	}
	return &azureBackend{
		account:   account,
		container: strings.Trim(container, "/"),
		prefix:    strings.Trim(dest.Endpoint, "/"),
		key:       creds.AccessKey,
		client:    &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (b *azureBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	u := b.objectURL(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.Header.Set("x-ms-version", "2020-10-02")
	b.sign(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("azure push %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (b *azureBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	u := b.objectURL(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-ms-version", "2020-10-02")
	b.sign(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("azure pull %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (b *azureBackend) List(ctx context.Context, prefix string) ([]string, error) {
	u := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", b.account, b.container)
	if prefix != "" {
		u += "&prefix=" + url.QueryEscape(prefix)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-ms-version", "2020-10-02")
	b.sign(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("azure list %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseAzureBlobNames(string(body)), nil
}

func (b *azureBackend) objectURL(objectKey string) string {
	blob := objectKey
	if b.prefix != "" {
		blob = strings.Trim(b.prefix, "/") + "/" + strings.TrimLeft(objectKey, "/")
	}
	return fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", b.account, b.container, escapeAzurePath(blob))
}

func escapeAzurePath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func parseAzureBlobNames(xml string) []string {
	var names []string
	for {
		i := strings.Index(xml, "<Name>")
		if i < 0 {
			break
		}
		xml = xml[i+6:]
		j := strings.Index(xml, "</Name>")
		if j < 0 {
			break
		}
		name := xml[:j]
		if strings.HasSuffix(name, ".iab") {
			names = append(names, name)
		}
		xml = xml[j+7:]
	}
	return names
}

func (b *azureBackend) sign(req *http.Request) {
	now := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", now)
	canonicalHeaders := "x-ms-date:" + now + "\n"
	if v := req.Header.Get("x-ms-blob-type"); v != "" {
		canonicalHeaders += "x-ms-blob-type:" + v + "\n"
	}
	canonicalHeaders += "x-ms-version:" + req.Header.Get("x-ms-version") + "\n"
	canonicalizedResource := "/" + b.account + req.URL.Path
	stringToSign := strings.ToUpper(req.Method) + "\n\n\n\n\n\n\n\n\n\n\n\n" + canonicalHeaders + canonicalizedResource
	mac := hmac.New(sha256.New, decodeAzureKey(b.key))
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set("Authorization", "SharedKey "+b.account+":"+sig)
}

func decodeAzureKey(key string) []byte {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return []byte(key)
	}
	return b
}
