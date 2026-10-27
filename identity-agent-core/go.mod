module identity-agent-core

go 1.25.0

require (
	github.com/cloudflare/circl v1.6.3
	github.com/go-chi/chi/v5 v5.2.5
	github.com/go-chi/cors v1.2.2
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/jezek/xgb v1.3.1
	github.com/mr-tron/base58 v1.2.0
	github.com/pkg/sftp v1.13.10
	github.com/zeebo/blake3 v0.2.4
	golang.ngrok.com/ngrok v1.13.0
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	modernc.org/sqlite v1.46.1
)

require (
	github.com/hashicorp/yamux v0.1.2 // indirect
	golang.org/x/mobile v0.0.0-20260813181013-1960c775504c // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

require (
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto v0.0.0
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto v0.0.0
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/grapeid/keri-go v0.1.5
	github.com/inconshreveable/log15 v3.0.0-testing.5+incompatible // indirect
	github.com/inconshreveable/log15/v3 v3.0.0-testing.5 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.ngrok.com/muxado/v2 v2.0.1 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

tool golang.org/x/mobile/cmd/gobind

replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto => ./relayproto

replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto => ./witnessproto
