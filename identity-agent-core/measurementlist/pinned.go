package measurementlist

// PinnedKeyID and PinnedKeyHex are the publisher key this build trusts, set at
// build time:
//
//	go build -ldflags "-X identity-agent-core/measurementlist.PinnedKeyHex=<hex> \
//	                   -X identity-agent-core/measurementlist.PinnedKeyID=<id>"
//
// Empty by default, so a build that is not given a key verifies no list. It
// is deliberately not read from the environment: whoever starts the process
// is not who decides whom the owner trusts.
var (
	PinnedKeyID  = ""
	PinnedKeyHex = ""
)

// Pinned returns the key compiled into this build.
func Pinned() (PinnedKey, error) { return ParseKeyHex(PinnedKeyID, PinnedKeyHex) }
