package sandbox

import "identity-agent-core/appmanifest"

// A sandboxed app's manifest is its contract with whatever runs it, published
// as package appmanifest. The runtime names its types here so its own code
// reads as before.
type (
	AppManifest        = appmanifest.AppManifest
	ProvidedCapability = appmanifest.ProvidedCapability
	HostControlSpec    = appmanifest.HostControlSpec
	PlatformBinary     = appmanifest.PlatformBinary
	ContainerConfig    = appmanifest.ContainerConfig
	BinaryConfig       = appmanifest.BinaryConfig
	ResourceLimits     = appmanifest.ResourceLimits
	NetworkPermissions = appmanifest.NetworkPermissions
	Capabilities       = appmanifest.Capabilities
)

// LoadManifest reads and checks one manifest (appmanifest.LoadManifest).
func LoadManifest(path string) (*AppManifest, error) { return appmanifest.LoadManifest(path) }

// LoadManifestsFromDir reads and checks every manifest in dir
// (appmanifest.LoadManifestsFromDir).
func LoadManifestsFromDir(dir string) ([]*AppManifest, error) {
	return appmanifest.LoadManifestsFromDir(dir)
}
