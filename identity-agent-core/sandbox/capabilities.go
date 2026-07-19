package sandbox

import "sort"

// CapabilityInfo describes one functional capability an installed plug-in offers,
// aggregated from manifests' provides[]. This is the discovery surface the agent
// exposes so a caller can see what the agent can actually do — the read side of the
// agent's governed capability endpoint. (Invoking a capability is governed separately.)
type CapabilityInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	RequestContract string `json:"request_contract,omitempty"`
	ProvidedBy      string `json:"provided_by"` // the plug-in (app) id that offers it
	HostControl     bool   `json:"host_control"`
}

// ProvidedCapabilities returns every functional capability offered by a loaded
// plug-in, aggregated across all manifests' provides[], sorted by id. Discovery only:
// it reports what is offered, not whether the caller is authorized to invoke it.
func (m *Manager) ProvidedCapabilities() []CapabilityInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var caps []CapabilityInfo
	for appID, manifest := range m.manifests {
		for _, p := range manifest.Provides {
			caps = append(caps, CapabilityInfo{
				ID:              p.ID,
				Name:            p.Name,
				Description:     p.Description,
				RequestContract: p.RequestContract,
				ProvidedBy:      appID,
				HostControl:     p.HostControl,
			})
		}
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].ID < caps[j].ID })
	return caps
}
