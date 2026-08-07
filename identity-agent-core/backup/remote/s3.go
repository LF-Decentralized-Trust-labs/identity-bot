package remote

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type s3Backend struct {
	bucket   string
	endpoint string
	region   string
	access   string
	secret   string
	token    string
	client   *http.Client
}

func NewS3Backend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	if dest.Bucket == "" {
		return nil, fmt.Errorf("s3 destination requires cloud_bucket")
	}
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return nil, fmt.Errorf("s3 destination requires access_key and secret_key")
	}
	endpoint := strings.TrimRight(dest.Endpoint, "/")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", dest.Bucket, defaultRegion(dest.Region))
	}
	return &s3Backend{
		bucket:   dest.Bucket,
		endpoint: endpoint,
		region:   defaultRegion(dest.Region),
		access:   creds.AccessKey,
		secret:   creds.SecretKey,
		token:    creds.SessionToken,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func defaultRegion(region string) string {
	if region == "" {
		return "us-east-1"
	}
	return region
}

func (b *s3Backend) Push(ctx context.Context, objectKey string, data []byte) error {
	u := b.objectURL(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	b.sign(req, data)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 push %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (b *s3Backend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	u := b.objectURL(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	b.sign(req, nil)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("s3 pull %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (b *s3Backend) List(ctx context.Context, prefix string) ([]string, error) {
	u, err := url.Parse(b.endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("list-type", "2")
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	b.sign(req, nil)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("s3 list %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseS3ListKeys(body), nil
}

func (b *s3Backend) objectURL(objectKey string) string {
	base := strings.TrimRight(b.endpoint, "/")
	if strings.Contains(base, b.bucket+".") || strings.HasSuffix(base, "/"+b.bucket) {
		return base + "/" + objectKey
	}
	return base + "/" + b.bucket + "/" + objectKey
}

func parseS3ListKeys(xml []byte) []string {
	text := string(xml)
	var keys []string
	for {
		i := strings.Index(text, "<Key>")
		if i < 0 {
			break
		}
		text = text[i+5:]
		j := strings.Index(text, "</Key>")
		if j < 0 {
			break
		}
		keys = append(keys, text[:j])
		text = text[j+6:]
	}
	return keys
}

func (b *s3Backend) sign(req *http.Request, body []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	if b.token != "" {
		req.Header.Set("X-Amz-Security-Token", b.token)
	}
	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := canonicalQueryString(req.URL.Query())
	signedHeaders, canonicalHeaders := canonicalHeaderMap(req.Header)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	credentialScope := dateStamp + "/" + b.region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := awsV4Signature(b.secret, dateStamp, b.region, "s3", stringToSign)
	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		b.access, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

func canonicalQueryString(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := v[k]
		sort.Strings(vals)
		for _, val := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(val))
		}
	}
	return strings.Join(parts, "&")
}

func canonicalHeaderMap(h http.Header) (signed string, canonical string) {
	keys := make([]string, 0, len(h))
	lower := map[string][]string{}
	for k, vals := range h {
		lk := strings.ToLower(k)
		keys = append(keys, lk)
		trimmed := make([]string, len(vals))
		for i, v := range vals {
			trimmed[i] = strings.TrimSpace(v)
		}
		lower[lk] = trimmed
	}
	sort.Strings(keys)
	var canonParts []string
	for _, k := range keys {
		canonParts = append(canonParts, k+":"+strings.Join(lower[k], ","))
	}
	return strings.Join(keys, ";"), strings.Join(canonParts, "\n") + "\n"
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func awsV4Signature(secret, dateStamp, region, service, stringToSign string) string {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
