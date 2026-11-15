# Pinned TPM manufacturer roots

`tpmroots/*.pem` are the trust anchors an endorsement-key certificate must chain to
(`tpm_key_certify.go`, `verifyEKCertificate`), and `../tpmintermediates/*.pem` the issuers a
chain must pass through (the leaf's direct issuer must be one of them, or a pinned root with none
beneath it), so a front end need not send them. They come from Microsoft's trusted TPM root
certificate list, the one Windows device attestation uses, and the project decided on 2026-11-14 to
trust it for **physical TPM chips only**. `SOURCE.txt` records the package URL, its SHA-256 and the date
it was fetched, and lists every certificate with its maker and class.

**Classes.** `tools/tpmroots` marks each certificate *physical*, *virtual* or *unclassified* (the
evidence for each is at the top of `SOURCE.txt`). Only physical ones are pinned in `tpmroots` and
`tpmintermediates`. Microsoft's own TPM issuers (`MSFT-KEYID-…`: the software TPM of Hyper-V and Azure)
are written to `../tpmvirtual`, which is never trusted and only lets a chain through one be refused by
name. A certificate that cannot be classified is written nowhere. The package does not itself name a
certificate as virtual: that reading rests on the vendor id and on Microsoft's own statements, and a
virtual TPM that chains through an issuer this tool took for physical would be accepted, so any
reclassification is a reviewed change to `classify`.

**Not pinned.** Six STMicroelectronics issuers (and one Qualcomm one) are among the certificates Go's X.509
reader refuses (a malformed serial number), so a chain through one fails: a PC whose TPM is an
STMicroelectronics chip cannot sign in yet.

To update: `secureenclave/tpmroots/update.sh` (needs `curl`, `cabextract`, `osslsigncode`, Go; works on
macOS, Linux and Windows under Git Bash). It checks Microsoft's Authenticode signature on the package
against Microsoft Root Certificate Authority 2011 (`tools/tpmroots/microsoft-root-2011.pem`), prints the
package's SHA-256 and stops; run it again with that hash to write the files. Read the diff and
`SOURCE.txt` before committing. Nothing else changes.

What this trusts: a certificate chain to one of these roots through a pinned physical issuer, and a leaf
marked as a TCG endorsement key certificate. The proof records the issuer and its class
(`ek_issuer`, `ek_class`). The owner's `tpm_keys` setting is what says a TPM key is accepted at all.
