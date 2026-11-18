package binding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// InviteVersion names the form an organisation signs an invite in. It opens the signed bytes, so a key that signs
// this signs nothing else that looks like it (ADR-082).
const InviteVersion = "ORGASK1"

// Invite is what the organisation signs, with its own identity key, to say an Ask is its own and where it takes
// the statement. It is not the Ask's JSON: it is a fixed form of plain ASCII, so an organisation written in any
// language produces the same bytes, whatever name it gives itself. The two names are signed as the SHA-256 of their
// UTF-8 bytes in lower-case hex, so what the person is shown cannot be changed by a host that relays the Ask.
type Invite struct {
	V          string `json:"v"`
	Org        string `json:"org"`
	Site       string `json:"site"`
	RecordSite string `json:"record_site"`
	Role       string `json:"role"`
	Invite     string `json:"invite"`
	RedeemURL  string `json:"redeem_url"`
	OrgName    string `json:"org_name_sha256"`
	SiteName   string `json:"site_name_sha256"`
}

var (
	redeemURLForm = regexp.MustCompile(`^https?://[A-Za-z0-9._~:/%-]{1,500}$`)
	hexDigest     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NewInvite makes the form from what the Ask says. orgName and siteName are the names as the Ask shows them;
// invite is the digest of the invite's code.
func NewInvite(org, orgName, site, siteName, recordSite, role, invite, redeemURL string) Invite {
	h := func(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
	return Invite{V: InviteVersion, Org: org, Site: site, RecordSite: recordSite, Role: role, Invite: invite,
		RedeemURL: redeemURL, OrgName: h(orgName), SiteName: h(siteName)}
}

// SignedBytes is the one string the organisation signs: the fields in this order, as JSON with no spaces.
func (i Invite) SignedBytes() []byte { b, _ := json.Marshal(i); return b }

// Check refuses a form that is not plain ASCII of the shapes it names.
func (i Invite) Check() error {
	switch {
	case i.V != InviteVersion:
		return errors.New("that is not an invite an organization signs")
	case i.Role != RolePerson && i.Role != RoleOwner:
		return errors.New("an invite is for a person or the owner")
	case !identifierForm.MatchString(i.Org) || !identifierForm.MatchString(i.Site) || !identifierForm.MatchString(i.RecordSite) ||
		!identifierForm.MatchString(i.Invite):
		return errors.New("every identifier and the invite are written as an identifier is: letters, digits, - and _")
	case !redeemURLForm.MatchString(i.RedeemURL):
		return errors.New("the address that takes the statement is plain ASCII with no query")
	case !hexDigest.MatchString(i.OrgName) || !hexDigest.MatchString(i.SiteName):
		return errors.New("a name is signed as the lower-case hex SHA-256 of its UTF-8 bytes")
	}
	return nil
}

// SignInvite signs the form with the organisation's identity seed.
func SignInvite(i Invite, seed []byte) (string, error) {
	if err := i.Check(); err != nil {
		return "", err
	}
	return login.SignString(string(i.SignedBytes()), seed)
}

// VerifyInvite checks a signature over the form against the organisation's key, as its own key log gives it.
func VerifyInvite(i Invite, sig string, key []byte) error {
	if err := i.Check(); err != nil {
		return err
	}
	if err := iacrypto.CheckEd25519PublicKey(key); err != nil {
		return err
	}
	ok, err := login.VerifyString(string(i.SignedBytes()), sig, key)
	if err != nil || !ok {
		return errors.New("the organization did not sign this request")
	}
	return nil
}
