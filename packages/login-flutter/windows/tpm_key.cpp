#include "tpm_key.h"

#include <windows.h>
#include <dpapi.h>
#include <ncrypt.h>
#include <shlobj.h>
#include <tbs.h>

// NOT COMPILED OR RUN ON WINDOWS: no Windows machine was available when this was written.
// What was run is everything under tpm2.cpp, on Linux against a software TPM (test/). What
// is Windows's own and unproved is here: the TBS calls, DPAPI, the file location, and the
// CNG property that fetches an EK certificate the TPM does not carry.

namespace tpm_key {
namespace {

// One TBS context per call: transient objects belong to it and go with it.
struct Tbs {
  TBS_HCONTEXT ctx = 0;
  ~Tbs() { if (ctx) Tbsip_Context_Close(ctx); }
  bool Open(Failure* why) {
    // TBS_CONTEXT_PARAMS2 as the Windows SDK declares it (version 2, with the TPM 2.0 bit
    // set), spelt here because not every toolchain's tbs.h has it.
    struct Params2 { UINT32 version; UINT32 flags; } p{2, 1u << 1 /*includeTpm20*/};
    TBS_RESULT r = Tbsi_Context_Create(reinterpret_cast<const TBS_CONTEXT_PARAMS*>(&p), &ctx);
    if (r != TBS_SUCCESS) {
      if (why) *why = {"no_tpm", "this computer has no TPM 2.0 the app can use (TBS status 0x" + std::to_string(static_cast<unsigned long>(r)) + ")", 0};
      return false;
    }
    return true;
  }
  tpm2::Transport Transport() {
    return [this](const Bytes& cmd, Bytes* resp) {
      resp->assign(4096, 0);
      UINT32 n = static_cast<UINT32>(resp->size());
      TBS_RESULT r = Tbsip_Submit_Command(ctx, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd.data(),
                                          static_cast<UINT32>(cmd.size()), resp->data(), &n);
      if (r != TBS_SUCCESS) return false;
      resp->resize(n);
      return true;
    };
  }
};

std::wstring Dir() {
  PWSTR local = nullptr;
  std::wstring dir;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local))) {
    dir = std::wstring(local) + L"\\identity-agent";
    CreateDirectoryW(dir.c_str(), nullptr);
    dir += L"\\login_flutter";
    CreateDirectoryW(dir.c_str(), nullptr);
  }
  if (local) CoTaskMemFree(local);
  return dir;
}

std::wstring Path(const std::string& name) {
  std::wstring w;
  for (char c : name) {  // a label is made of the app's own characters: keep to a safe set
    w += (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-') ? static_cast<wchar_t>(c) : L'_';
  }
  return Dir() + L"\\" + w + L".blob";
}

// The key blob is the TPM's (its private part opens only in this TPM, under this storage
// key), and DPAPI keeps it to this Windows user as well.
struct DpapiFiles : tpm2::BlobStore {
  bool Put(const std::string& name, const Bytes& v) override {
    DATA_BLOB in{static_cast<DWORD>(v.size()), const_cast<BYTE*>(v.data())}, out{};
    if (!CryptProtectData(&in, L"identity-agent login_flutter key", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    HANDLE f = CreateFileW(Path(name).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD wrote = 0;
    bool ok = f != INVALID_HANDLE_VALUE && WriteFile(f, out.pbData, out.cbData, &wrote, nullptr) && wrote == out.cbData;
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    LocalFree(out.pbData);
    return ok;
  }
  std::optional<Bytes> Get(const std::string& name) override {
    HANDLE f = CreateFileW(Path(name).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return std::nullopt;
    DWORD size = GetFileSize(f, nullptr), got = 0;
    Bytes raw(size == INVALID_FILE_SIZE || size > (1u << 20) ? 0 : size);
    bool ok = !raw.empty() && ReadFile(f, raw.data(), size, &got, nullptr) && got == size;
    CloseHandle(f);
    if (!ok) return std::nullopt;
    DATA_BLOB in{static_cast<DWORD>(raw.size()), raw.data()}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return std::nullopt;
    Bytes v(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return v;
  }
};

// The certificate a TPM without one in its own memory can still have: Windows fetches the
// ones its makers publish (PCP_EKCERT on the Platform Crypto Provider).
std::optional<Bytes> EkCertificateFromWindows() {
  NCRYPT_PROV_HANDLE p = 0;
  if (NCryptOpenStorageProvider(&p, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS) return std::nullopt;
  DWORD n = 0;
  std::optional<Bytes> out;
  if (NCryptGetProperty(p, L"PCP_EKCERT", nullptr, 0, &n, 0) == ERROR_SUCCESS && n > 0 && n <= 8192) {
    Bytes b(n);
    if (NCryptGetProperty(p, L"PCP_EKCERT", b.data(), n, &n, 0) == ERROR_SUCCESS) {
      b.resize(n);
      out = b;
    }
  }
  NCryptFreeObject(p);
  return out;
}

}  // namespace

std::optional<Bytes> PublicPoint(const std::string& label, Failure*) {
  DpapiFiles store;
  return tpm2::PublicPointOf(store, label);
}

std::optional<tpm2::Enrolment> Enrol(const std::string& label, Failure* why) {
  Tbs tbs;
  if (!tbs.Open(why)) return std::nullopt;
  tpm2::Device dev(tbs.Transport());
  DpapiFiles store;
  return tpm2::MakeEnrolment(dev, store, label, EkCertificateFromWindows, why);
}

std::optional<tpm2::Attested> Attest(const std::string& label, const Bytes& challenge, const Bytes& credential,
                                     const Bytes& secret, Failure* why) {
  Tbs tbs;
  if (!tbs.Open(why)) return std::nullopt;
  tpm2::Device dev(tbs.Transport());
  DpapiFiles store;
  return tpm2::Attest(dev, store, label, challenge, credential, secret, why);
}

std::optional<Bytes> SignDigest(const std::string& label, const Bytes& digest, Failure* why) {
  Tbs tbs;
  if (!tbs.Open(why)) return std::nullopt;
  tpm2::Device dev(tbs.Transport());
  DpapiFiles store;
  return tpm2::SignDigest(dev, store, label, digest, why);
}

std::optional<Bytes> SignCall(const std::string& label, const Bytes& message, Failure* why) {
  return SignDigest(label, tpm2::Sha256(message), why);
}

}  // namespace tpm_key
