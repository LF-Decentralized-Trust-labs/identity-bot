#!/usr/bin/env bash
# Updates the pinned TPM manufacturer roots and issuers from Microsoft's trusted TPM
# root certificate list (the package Windows device attestation uses). Run from
# identity-agent-core; needs cabextract and Go. Review `git diff --stat` and SOURCE.txt before committing:
# what is pinned is whom the Identity Agent trusts to say a key is in a real TPM.
set -euo pipefail
cd "$(dirname "$0")/../.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
url="https://go.microsoft.com/fwlink/?linkid=2097925"
curl -fsSL -o "$work/TrustedTpm.cab" "$url"
sum="$(sha256sum "$work/TrustedTpm.cab" | cut -d' ' -f1)"
mkdir "$work/x"
cabextract -q -d "$work/x" "$work/TrustedTpm.cab" || true   # warns of trailing bytes
rm -f secureenclave/tpmroots/*.pem secureenclave/tpmintermediates/*.pem
go run ./tools/tpmroots -in "$work/x" -out secureenclave/tpmroots -intermediates secureenclave/tpmintermediates -source "$url" -sha256 "$sum"
