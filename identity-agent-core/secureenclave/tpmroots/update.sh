#!/usr/bin/env bash
# Updates the pinned TPM manufacturer roots and issuers from Microsoft's trusted TPM
# root certificate list (the package Windows device attestation uses). Run from anywhere;
# needs curl, cabextract, osslsigncode and Go. Works on macOS, Linux and Windows (Git Bash).
#
#   update.sh                 fetch, verify Microsoft's signature, print the package's SHA-256, stop
#   update.sh <sha256>        the same, and write the files only if the package is that one
#
# The second form is the gate: read the first run's hash, say it is the package you mean,
# and only then are the pinned files replaced. Review `git diff --stat` and SOURCE.txt before
# committing: what is pinned is whom the Identity Agent trusts to say a key is in a physical TPM chip.
set -euo pipefail
cd "$(dirname "$0")/../.."
want="${1:-}"
for tool in curl cabextract osslsigncode go; do
  command -v "$tool" >/dev/null || { echo "update.sh: $tool is needed" >&2; exit 2; }
done
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
url="https://go.microsoft.com/fwlink/?linkid=2097925"
root=tools/tpmroots/microsoft-root-2011.pem   # Microsoft Root Certificate Authority 2011, committed; SHA-256 847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61
curl -fsSL -o "$work/TrustedTpm.cab" "$url"

# Microsoft signs the package (Authenticode). A download that does not verify against Microsoft's
# root is not Microsoft's, whatever its hash.
osslsigncode verify -CAfile "$root" -TSA-CAfile "$root" -in "$work/TrustedTpm.cab" >"$work/verify.txt" 2>&1 ||
  { cat "$work/verify.txt" >&2; echo "update.sh: the package's Microsoft signature does not verify; nothing was changed" >&2; exit 1; }

sum="$(sha256 "$work/TrustedTpm.cab")"
echo "package SHA-256: $sum (Microsoft signature verified)"
if [ -z "$want" ]; then
  echo "nothing written; run again with this hash to replace the pinned files: $0 $sum"
  exit 3
fi
if [ "$want" != "$sum" ]; then
  echo "update.sh: the package is $sum, not the $want you named; nothing was changed" >&2
  exit 1
fi

# cabextract warns of trailing bytes and still succeeds; any other failure stops the script.
mkdir "$work/x"
cabextract -q -d "$work/x" "$work/TrustedTpm.cab"
listed=$(( $(cabextract -l "$work/TrustedTpm.cab" 2>/dev/null | grep -c ' | ') - 1 ))
got="$(find "$work/x" -type f | wc -l | tr -d ' ')"
if [ "$got" != "$listed" ] || [ "$got" -lt 100 ]; then
  echo "update.sh: the cabinet lists $listed files and $got were extracted; nothing was changed" >&2
  exit 1
fi

mkdir -p secureenclave/tpmvirtual
rm -f secureenclave/tpmroots/*.pem secureenclave/tpmintermediates/*.pem secureenclave/tpmvirtual/*.pem
go run ./tools/tpmroots -in "$work/x" -out secureenclave/tpmroots -intermediates secureenclave/tpmintermediates -virtual secureenclave/tpmvirtual -source "$url" -sha256 "$sum"
