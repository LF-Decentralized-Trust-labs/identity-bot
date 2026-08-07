package relay

// IARELAY protocol shapes (consumer side).
const JSONVersion = "IARELAY10JSON"

type ServiceDescriptor struct {
	V                  string         `json:"v"`
	ProtocolVersion    string         `json:"protocol_version"`
	DidWebsSpecVersion string         `json:"didwebs_spec_version"`
	RelayAID           string         `json:"relay_aid"`
	Apex               string         `json:"apex"`
	TunnelEndpoint     string         `json:"tunnel_endpoint"`
	AllocateEndpoint   string         `json:"allocate_endpoint"`
	ReleaseEndpoint    string         `json:"release_endpoint"`
	HeartbeatEndpoint  string         `json:"heartbeat_endpoint"`
	HeartbeatInterval  int            `json:"heartbeat_interval_sec"`
	PathAllowlist      []string       `json:"path_allowlist"`
	RateLimits         map[string]int `json:"rate_limits"`
}

type AllocateResponse struct {
	PublicURL       string `json:"public_url"`
	PublicHostname  string `json:"public_hostname"`
	AllocationToken string `json:"allocation_token"`
	TunnelEndpoint  string `json:"tunnel_endpoint"`
}

type EnrollResponse struct {
	Enrolled        bool   `json:"enrolled"`
	EnrollmentAID   string `json:"enrollment_aid"`
	EnrollmentToken string `json:"enrollment_token"`
	TunnelEndpoint  string `json:"tunnel_endpoint"`
}
