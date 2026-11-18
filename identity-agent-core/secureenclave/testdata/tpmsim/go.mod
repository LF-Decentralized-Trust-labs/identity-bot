module tpmsim

go 1.26

require (
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.11
	identity-agent-core v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260915221818-a6c0685fb9fc // indirect
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto v0.0.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-sev-guest v0.14.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grapeid/keri-go v0.5.1-0.20261114214057-6f13a662d95e // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace identity-agent-core => ../../..

replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto => ../../../relayproto

replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto => ../../../witnessproto
