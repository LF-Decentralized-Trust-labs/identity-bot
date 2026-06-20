module identity-bot/pqc-poc

go 1.25.0

require github.com/open-quantum-safe/liboqs-go v0.0.0-20250611120000-000000000000

require (
	golang.org/x/mobile v0.0.0-20260611195102-4dd8f1dbf5d2 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/tools v0.46.0 // indirect
)

replace github.com/open-quantum-safe/liboqs-go => /tmp/liboqs-go

tool golang.org/x/mobile/cmd/gobind
