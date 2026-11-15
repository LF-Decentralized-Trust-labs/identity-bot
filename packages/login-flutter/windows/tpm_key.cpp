#include "tpm_key.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <codecvt>
#include <locale>

// NOT COMPILED OR RUN: no Windows machine was available when this was written.
//
// What is here is what CNG documents: a persisted, non-exportable ECDSA P-256 key in the
// Platform Crypto Provider (the TPM), its public point, and signatures. What is NOT here is
// the evidence the Identity Agent asks of a TPM key (tpm_key_certify.go: a TPM2_Certify by an
// attestation key, the EK certificate chain and a TPM2_ActivateCredential result): the core
// states that its half of that exchange (the TPM2_MakeCredential blob the app must activate)
// is not built and that no TPM manufacturer root is pinned yet, so evidence made now could
// not be accepted. See README, "Not built".

namespace tpm_key {
namespace {

std::wstring Wide(const std::string& s) {
  return std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes("identity-agent.login_flutter." + s);
}

struct Provider {
  NCRYPT_PROV_HANDLE h = 0;
  ~Provider() { if (h) NCryptFreeObject(h); }
};
struct Key {
  NCRYPT_KEY_HANDLE h = 0;
  ~Key() { if (h) NCryptFreeObject(h); }
};

bool Fail(Failure* why, const char* code, SECURITY_STATUS s) {
  if (why) {
    why->code = code;
    why->message = std::string(code) + " failed, status 0x" + std::to_string(static_cast<unsigned long>(s));
  }
  return false;
}

bool Open(Provider& p, Failure* why) {
  SECURITY_STATUS s = NCryptOpenStorageProvider(&p.h, MS_PLATFORM_CRYPTO_PROVIDER, 0);
  return s == ERROR_SUCCESS || Fail(why, "no_tpm", s);
}

std::optional<Bytes> Point(NCRYPT_KEY_HANDLE k, Failure* why) {
  DWORD n = 0;
  SECURITY_STATUS s = NCryptExportKey(k, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &n, 0);
  if (s != ERROR_SUCCESS) { Fail(why, "export", s); return std::nullopt; }
  Bytes blob(n);
  s = NCryptExportKey(k, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), n, &n, 0);
  if (s != ERROR_SUCCESS) { Fail(why, "export", s); return std::nullopt; }
  auto* h = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
  if (h->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || h->cbKey != 32 || n < sizeof(*h) + 64) {
    Fail(why, "not_p256", 0);
    return std::nullopt;
  }
  Bytes out{0x04};
  out.insert(out.end(), blob.begin() + sizeof(*h), blob.begin() + sizeof(*h) + 64);
  return out;
}

// CNG gives r then s, 32 bytes each; the Identity Agent reads ASN.1 DER.
Bytes ToDer(const unsigned char* raw) {
  auto part = [](const unsigned char* v) {
    Bytes b(v, v + 32);
    while (b.size() > 1 && b[0] == 0) b.erase(b.begin());
    if (b[0] & 0x80) b.insert(b.begin(), 0);
    Bytes out{0x02, static_cast<unsigned char>(b.size())};
    out.insert(out.end(), b.begin(), b.end());
    return out;
  };
  Bytes r = part(raw), s = part(raw + 32);
  Bytes out{0x30, static_cast<unsigned char>(r.size() + s.size())};
  out.insert(out.end(), r.begin(), r.end());
  out.insert(out.end(), s.begin(), s.end());
  return out;
}

std::optional<Bytes> Sign(const std::string& label, const Bytes& digest, Failure* why) {
  Provider p;
  if (!Open(p, why)) return std::nullopt;
  Key k;
  SECURITY_STATUS s = NCryptOpenKey(p.h, &k.h, Wide(label).c_str(), 0, 0);
  if (s != ERROR_SUCCESS) { Fail(why, "no_key", s); return std::nullopt; }
  DWORD n = 0;
  s = NCryptSignHash(k.h, nullptr, const_cast<PBYTE>(digest.data()), static_cast<DWORD>(digest.size()), nullptr, 0, &n, 0);
  if (s != ERROR_SUCCESS || n != 64) { Fail(why, "sign", s); return std::nullopt; }
  Bytes sig(n);
  s = NCryptSignHash(k.h, nullptr, const_cast<PBYTE>(digest.data()), static_cast<DWORD>(digest.size()), sig.data(), n, &n, 0);
  if (s != ERROR_SUCCESS) { Fail(why, "sign", s); return std::nullopt; }
  return ToDer(sig.data());
}

Bytes Sha256(const Bytes& m) {
  Bytes out(32);
  BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(m.data()), static_cast<ULONG>(m.size()), out.data(), 32);
  return out;
}

}  // namespace

std::optional<Bytes> PublicPoint(const std::string& label, Failure* why) {
  Provider p;
  if (!Open(p, why)) return std::nullopt;
  Key k;
  SECURITY_STATUS s = NCryptOpenKey(p.h, &k.h, Wide(label).c_str(), 0, 0);
  if (s == NTE_BAD_KEYSET) return std::nullopt;  // no key yet: not a failure
  if (s != ERROR_SUCCESS) { Fail(why, "open", s); return std::nullopt; }
  return Point(k.h, why);
}

std::optional<Bytes> CreateKey(const std::string& label, Failure* why) {
  Provider p;
  if (!Open(p, why)) return std::nullopt;
  {
    Key old;
    if (NCryptOpenKey(p.h, &old.h, Wide(label).c_str(), 0, 0) == ERROR_SUCCESS) {
      NCryptDeleteKey(old.h, 0);
      old.h = 0;  // NCryptDeleteKey frees the handle
    }
  }
  Key k;
  SECURITY_STATUS s = NCryptCreatePersistedKey(p.h, &k.h, BCRYPT_ECDSA_P256_ALGORITHM, Wide(label).c_str(), 0, 0);
  if (s != ERROR_SUCCESS) { Fail(why, "create", s); return std::nullopt; }
  DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
  s = NCryptSetProperty(k.h, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage), NCRYPT_PERSIST_FLAG);
  if (s != ERROR_SUCCESS) { Fail(why, "usage", s); return std::nullopt; }
  s = NCryptFinalizeKey(k.h, 0);
  if (s != ERROR_SUCCESS) { Fail(why, "finalize", s); return std::nullopt; }
  return Point(k.h, why);
}

std::optional<Bytes> SignCall(const std::string& label, const Bytes& message, Failure* why) {
  return Sign(label, Sha256(message), why);
}

std::optional<Bytes> SignDigest(const std::string& label, const Bytes& digest, Failure* why) {
  return Sign(label, digest, why);
}

}  // namespace tpm_key
