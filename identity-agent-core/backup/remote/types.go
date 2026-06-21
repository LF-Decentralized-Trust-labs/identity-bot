package remote

// DestinationConfig describes a user-managed remote target.
type DestinationConfig struct {
	Provider      string
	Bucket        string
	Prefix        string
	Endpoint      string
	Region        string
	RemoteURL     string
}

// CredentialSecrets holds provider credentials for remote push/pull.
type CredentialSecrets struct {
	AccessKey          string
	SecretKey          string
	SessionToken       string
	Username           string
	Password           string
	AccountName        string
	ServiceAccountJSON string
}