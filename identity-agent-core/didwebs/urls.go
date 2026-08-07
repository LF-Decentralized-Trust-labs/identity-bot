package didwebs

import (
	"fmt"
	"net/url"
	"strings"
)

// ArtifactURLs holds derived did:webs artifact endpoints.
type ArtifactURLs struct {
	DID        string
	AID        string
	Host       string
	DidJSONURL string
	CesrURL    string
	OobiURL    string
}

// DeriveFromDID maps did:webs:host:aid → HTTPS artifact URLs (the contract §1).
func DeriveFromDID(did string) (*ArtifactURLs, error) {
	if !strings.HasPrefix(did, "did:webs:") {
		return nil, fmt.Errorf("not a did:webs identifier")
	}
	rest := strings.TrimPrefix(did, "did:webs:")
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("did:webs missing host or aid")
	}
	aid := parts[len(parts)-1]
	path := strings.ReplaceAll(rest, ":", "/")
	base := "https://" + path
	return &ArtifactURLs{
		DID: did, AID: aid, Host: strings.Join(parts[:len(parts)-1], ":"),
		DidJSONURL: base + "/did.json",
		CesrURL:    base + "/keri.cesr",
		OobiURL:    base + "/oobi",
	}, nil
}

// DeriveFromURL attempts did:webs resolution from a plain HTTPS URL.
func DeriveFromURL(raw string) (*ArtifactURLs, error) {
	if strings.HasPrefix(raw, "did:webs:") {
		return DeriveFromDID(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if q := u.Query().Get("did"); q != "" {
		decoded, _ := url.QueryUnescape(q)
		if strings.HasPrefix(decoded, "did:webs:") {
			return DeriveFromDID(decoded)
		}
	}
	// Path pattern /E.../did.json or /E.../
	path := strings.Trim(u.Path, "/")
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if strings.HasPrefix(seg, "E") && len(seg) >= 44 {
			host := u.Host
			if i > 0 {
				host = u.Host + "/" + strings.Join(segments[:i], "/")
			}
			did := fmt.Sprintf("did:webs:%s:%s", strings.ReplaceAll(host, "/", ":"), seg)
			if strings.Contains(host, "/") {
				did = fmt.Sprintf("did:webs:%s", strings.ReplaceAll(host, "/", ":")+":"+seg)
			}
			return DeriveFromDID(did)
		}
	}
	return nil, fmt.Errorf("could not derive did:webs from URL")
}
