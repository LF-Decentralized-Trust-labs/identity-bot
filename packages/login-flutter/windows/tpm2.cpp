#include "tpm2.h"

#include <array>
#include <cstdio>
#include <cstring>

namespace tpm2 {
namespace {

constexpr uint16_t ST_NO_SESSIONS = 0x8001, ST_SESSIONS = 0x8002;
constexpr uint32_t CC_Create = 0x153, CC_CreatePrimary = 0x131, CC_Load = 0x157, CC_FlushContext = 0x165,
                   CC_ActivateCredential = 0x147, CC_Certify = 0x148, CC_Sign = 0x15D, CC_StartAuthSession = 0x176,
                   CC_PolicySecret = 0x151, CC_NV_Read = 0x14E, CC_NV_ReadPublic = 0x169;
constexpr uint32_t RH_OWNER = 0x40000001, RH_NULL = 0x40000007, RS_PW = 0x40000009, RH_ENDORSEMENT = 0x4000000B;
constexpr uint16_t ALG_RSA = 1, ALG_SHA256 = 0x0B, ALG_NULL = 0x10, ALG_AES = 6, ALG_ECDSA = 0x18, ALG_ECC = 0x23,
                   ALG_CFB = 0x43;
constexpr uint16_t CURVE_P256 = 3;
constexpr uint32_t NV_EK_CERT_RSA = 0x01C00002;

// ---- marshalling, big-endian ----
struct W {
  Bytes b;
  W& u8(uint8_t v) { b.push_back(v); return *this; }
  W& u16(uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); return *this; }
  W& u32(uint32_t v) { u16(v >> 16); u16(v & 0xffff); return *this; }
  W& raw(const Bytes& v) { b.insert(b.end(), v.begin(), v.end()); return *this; }
  W& sized(const Bytes& v) { u16(static_cast<uint16_t>(v.size())); return raw(v); }
};
struct R {
  const Bytes& b; size_t at; bool bad = false;
  explicit R(const Bytes& v, size_t from = 0) : b(v), at(from) {}
  bool have(size_t n) { if (bad || at + n > b.size()) { bad = true; return false; } return true; }
  uint16_t u16() { if (!have(2)) return 0; uint16_t v = (b[at] << 8) | b[at + 1]; at += 2; return v; }
  uint32_t u32() { uint32_t hi = u16(); return (hi << 16) | u16(); }
  Bytes take(size_t n) { if (!have(n)) return {}; Bytes o(b.begin() + at, b.begin() + at + n); at += n; return o; }
  Bytes sized() { return take(u16()); }
};

Bytes Cat(std::initializer_list<Bytes> parts) { Bytes o; for (auto& p : parts) o.insert(o.end(), p.begin(), p.end()); return o; }

// A password session with the empty password, for one handle.
Bytes PasswordAuth() { return W().u32(RS_PW).u16(0).u8(0).u16(0).b; }
Bytes Auths(std::initializer_list<Bytes> each) {
  Bytes body;
  for (auto& a : each) body.insert(body.end(), a.begin(), a.end());
  return W().u32(static_cast<uint32_t>(body.size())).raw(body).b;
}

// ---- templates (TPMT_PUBLIC inside a TPM2B_PUBLIC) ----
constexpr uint32_t A_FIXEDTPM = 1 << 1, A_FIXEDPARENT = 1 << 4, A_SENSITIVEORIGIN = 1 << 5, A_USERWITHAUTH = 1 << 6,
                   A_ADMINWITHPOLICY = 1 << 7, A_NODA = 1 << 10, A_RESTRICTED = 1 << 16, A_DECRYPT = 1 << 17,
                   A_SIGN = 1 << 18;

Bytes SrkTemplate() {  // ECC P-256 storage key
  W t;
  t.u16(ALG_ECC).u16(ALG_SHA256).u32(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEORIGIN | A_USERWITHAUTH | A_NODA | A_RESTRICTED | A_DECRYPT)
      .u16(0)                                    // authPolicy
      .u16(ALG_AES).u16(128).u16(ALG_CFB)        // symmetric
      .u16(ALG_NULL)                             // scheme
      .u16(CURVE_P256).u16(ALG_NULL)             // curve, kdf
      .u16(0).u16(0);                            // unique x, y
  return W().sized(t.b).b;
}

Bytes EkRsa() {  // TCG EK Credential Profile, RSA 2048, the default (low-range) template
  static const uint8_t policy[32] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
                                     0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa};
  W t;
  t.u16(ALG_RSA).u16(ALG_SHA256)
      .u32(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEORIGIN | A_ADMINWITHPOLICY | A_RESTRICTED | A_DECRYPT)
      .sized(Bytes(policy, policy + 32))
      .u16(ALG_AES).u16(128).u16(ALG_CFB)
      .u16(ALG_NULL)
      .u16(2048).u32(0)
      .sized(Bytes(256, 0));
  return W().sized(t.b).b;
}

Bytes EccSigningKey(bool restricted) {
  W t;
  t.u16(ALG_ECC).u16(ALG_SHA256)
      .u32(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEORIGIN | A_USERWITHAUTH | A_SIGN | (restricted ? A_RESTRICTED : 0))
      .u16(0)
      .u16(ALG_NULL);  // no symmetric
  if (restricted) t.u16(ALG_ECDSA).u16(ALG_SHA256); else t.u16(ALG_NULL);
  t.u16(CURVE_P256).u16(ALG_NULL).u16(0).u16(0);
  return W().sized(t.b).b;
}

Bytes SensitiveEmpty() { return W().u16(4).u16(0).u16(0).b; }  // TPM2B_SENSITIVE_CREATE with no auth, no data

}  // namespace

// ---- SHA-256 (FIPS 180-4) ----
Bytes Sha256(const Bytes& data) {
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
      0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
      0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
      0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  Bytes m = data;
  uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
  m.push_back(0x80);
  while (m.size() % 64 != 56) m.push_back(0);
  for (int i = 7; i >= 0; i--) m.push_back(static_cast<uint8_t>(bits >> (8 * i)));
  auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
  for (size_t off = 0; off < m.size(); off += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = (m[off + 4 * i] << 24) | (m[off + 4 * i + 1] << 16) | (m[off + 4 * i + 2] << 8) | m[off + 4 * i + 3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g), t1 = hh + S1 + ch + K[i] + w[i];
      uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = S0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  Bytes out;
  for (uint32_t v : h) { out.push_back(v >> 24); out.push_back(v >> 16); out.push_back(v >> 8); out.push_back(v); }
  return out;
}

Bytes CertifyExtraData(const Bytes& challenge) {
  const std::string label = "identity-agent-tpm-key-certify-v1";
  Bytes in(label.begin(), label.end());
  in.push_back(0);
  in.insert(in.end(), challenge.begin(), challenge.end());
  return Sha256(in);
}

// ---- the device ----
bool Device::Run(uint16_t tag, uint32_t code, const Bytes& handles, const Bytes& auth, const Bytes& params, Reply* out, Failure* why) {
  W body;
  body.raw(handles).raw(auth).raw(params);
  Bytes cmd = W().u16(tag).u32(static_cast<uint32_t>(10 + body.b.size())).u32(code).raw(body.b).b;
  Bytes resp;
  if (!t_(cmd, &resp) || resp.size() < 10) {
    if (why) *why = {"no_tpm", "the TPM could not be reached", 0};
    return false;
  }
  R r(resp);
  r.u16();
  uint32_t size = r.u32();
  out->rc = r.u32();
  if (size != resp.size()) {
    if (why) *why = {"tpm_response", "the TPM's response is not the size it says", 0};
    return false;
  }
  out->body.assign(resp.begin() + 10, resp.end());
  if (out->rc != 0) {
    if (why) {
      char m[96];
      std::snprintf(m, sizeof m, "the TPM refused command 0x%x, response code 0x%x", code, out->rc);
      *why = {"tpm_refused", m, out->rc};
    }
    return false;
  }
  return true;
}

namespace {
// A response with sessions: handles first (n of them), then parameterSize and the parameters.
bool Params(const Bytes& body, size_t handles, Bytes* params, Failure* why) {
  R r(body, handles * 4);
  uint32_t n = r.u32();
  *params = r.take(n);
  if (r.bad) { if (why) *why = {"tpm_response", "the TPM's response is malformed", 0}; return false; }
  return true;
}
}  // namespace

std::optional<uint32_t> Device::Srk(Failure* why) {
  Reply rep;
  Bytes params = W().raw(SensitiveEmpty()).raw(SrkTemplate()).u16(0).u32(0).b;
  if (!Run(ST_SESSIONS, CC_CreatePrimary, W().u32(RH_OWNER).b, Auths({PasswordAuth()}), params, &rep, why)) return std::nullopt;
  R r(rep.body);
  return r.u32();
}

std::optional<uint32_t> Device::Ek(Bytes* pub, Failure* why) {
  Reply rep;
  Bytes params = W().raw(SensitiveEmpty()).raw(EkRsa()).u16(0).u32(0).b;
  if (!Run(ST_SESSIONS, CC_CreatePrimary, W().u32(RH_ENDORSEMENT).b, Auths({PasswordAuth()}), params, &rep, why)) return std::nullopt;
  R r(rep.body);
  uint32_t h = r.u32();
  Bytes p;
  if (!Params(rep.body, 1, &p, why)) return std::nullopt;
  R pr(p);
  Bytes outPublic = pr.sized();
  if (pr.bad) { if (why) *why = {"tpm_response", "the EK's public area is missing", 0}; return std::nullopt; }
  if (pub) *pub = W().sized(outPublic).b;
  return h;
}

std::optional<Created> Device::CreateAk(uint32_t parent, Failure* why) {
  Reply rep;
  Bytes params = W().raw(SensitiveEmpty()).raw(EccSigningKey(true)).u16(0).u32(0).b;
  if (!Run(ST_SESSIONS, CC_Create, W().u32(parent).b, Auths({PasswordAuth()}), params, &rep, why)) return std::nullopt;
  Bytes p;
  if (!Params(rep.body, 0, &p, why)) return std::nullopt;
  R r(p);
  Bytes priv = r.sized(), pub = r.sized();
  if (r.bad) { if (why) *why = {"tpm_response", "the key's blob is missing", 0}; return std::nullopt; }
  return Created{W().sized(priv).b, W().sized(pub).b};
}

std::optional<Created> Device::CreateAppKey(uint32_t parent, Failure* why) {
  Reply rep;
  Bytes params = W().raw(SensitiveEmpty()).raw(EccSigningKey(false)).u16(0).u32(0).b;
  if (!Run(ST_SESSIONS, CC_Create, W().u32(parent).b, Auths({PasswordAuth()}), params, &rep, why)) return std::nullopt;
  Bytes p;
  if (!Params(rep.body, 0, &p, why)) return std::nullopt;
  R r(p);
  Bytes priv = r.sized(), pub = r.sized();
  if (r.bad) { if (why) *why = {"tpm_response", "the key's blob is missing", 0}; return std::nullopt; }
  return Created{W().sized(priv).b, W().sized(pub).b};
}

std::optional<uint32_t> Device::Load(uint32_t parent, const Created& key, Failure* why) {
  Reply rep;
  if (!Run(ST_SESSIONS, CC_Load, W().u32(parent).b, Auths({PasswordAuth()}), Cat({key.private_blob, key.public_area}), &rep, why)) return std::nullopt;
  R r(rep.body);
  return r.u32();
}

void Device::Flush(uint32_t handle) {
  Reply rep;
  Run(ST_NO_SESSIONS, CC_FlushContext, {}, {}, W().u32(handle).b, &rep, nullptr);
}

std::optional<Bytes> Device::ActivateCredential(uint32_t ak, uint32_t ek, const Bytes& credential, const Bytes& secret, Failure* why) {
  // The policy session the EK's authPolicy asks for: PolicySecret of the endorsement hierarchy.
  Reply rep;
  Bytes nonce(16, 0x5a);
  Bytes start = W().sized(nonce).u16(0).u8(0x01 /*policy*/).u16(ALG_NULL).u16(ALG_SHA256).b;
  if (!Run(ST_NO_SESSIONS, CC_StartAuthSession, W().u32(RH_NULL).u32(RH_NULL).b, {}, start, &rep, why)) return std::nullopt;
  R sr(rep.body);
  uint32_t session = sr.u32();
  Bytes ps = W().u16(0).u16(0).u16(0).u32(0).b;  // nonceTPM, cpHashA, policyRef, expiration
  if (!Run(ST_SESSIONS, CC_PolicySecret, W().u32(RH_ENDORSEMENT).u32(session).b, Auths({PasswordAuth()}), ps, &rep, why)) {
    Flush(session);
    return std::nullopt;
  }
  Bytes sessionAuth = W().u32(session).u16(0).u8(0x01 /*continueSession*/).u16(0).b;
  bool ok = Run(ST_SESSIONS, CC_ActivateCredential, W().u32(ak).u32(ek).b, Auths({PasswordAuth(), sessionAuth}), Cat({credential, secret}), &rep, why);
  Flush(session);
  if (!ok) return std::nullopt;
  Bytes p;
  if (!Params(rep.body, 0, &p, why)) return std::nullopt;
  R r(p);
  Bytes released = r.sized();
  if (r.bad) { if (why) *why = {"tpm_response", "the TPM released nothing", 0}; return std::nullopt; }
  return released;
}

std::optional<Device::Certified> Device::Certify(uint32_t object, uint32_t signer, const Bytes& qualifying, Failure* why) {
  Reply rep;
  Bytes params = W().sized(qualifying).u16(ALG_NULL).b;
  if (!Run(ST_SESSIONS, CC_Certify, W().u32(object).u32(signer).b, Auths({PasswordAuth(), PasswordAuth()}), params, &rep, why)) return std::nullopt;
  Bytes p;
  if (!Params(rep.body, 0, &p, why)) return std::nullopt;
  R r(p);
  Bytes attest = r.sized();
  Bytes sig(p.begin() + r.at, p.end());
  if (r.bad || sig.empty()) { if (why) *why = {"tpm_response", "the certify response is malformed", 0}; return std::nullopt; }
  return Certified{attest, sig};
}

std::optional<Bytes> Device::Sign(uint32_t key, const Bytes& digest, Failure* why) {
  if (digest.size() != 32) { if (why) *why = {"bad_args", "a digest is 32 bytes", 0}; return std::nullopt; }
  Reply rep;
  Bytes params = W().sized(digest).u16(ALG_ECDSA).u16(ALG_SHA256).u16(0x8024).u32(RH_NULL).u16(0).b;
  if (!Run(ST_SESSIONS, CC_Sign, W().u32(key).b, Auths({PasswordAuth()}), params, &rep, why)) return std::nullopt;
  Bytes p;
  if (!Params(rep.body, 0, &p, why)) return std::nullopt;
  R r(p);
  uint16_t alg = r.u16();
  r.u16();
  Bytes rr = r.sized(), ss = r.sized();
  if (r.bad || alg != ALG_ECDSA || rr.size() > 32 || ss.size() > 32) { if (why) *why = {"tpm_response", "the signature is not ECDSA P-256", 0}; return std::nullopt; }
  Bytes out(64, 0);
  std::memcpy(out.data() + 32 - rr.size(), rr.data(), rr.size());
  std::memcpy(out.data() + 64 - ss.size(), ss.data(), ss.size());
  return out;
}

std::optional<Bytes> Device::ReadEkCertificate(Failure* why) {
  Reply rep;
  if (!Run(ST_NO_SESSIONS, CC_NV_ReadPublic, W().u32(NV_EK_CERT_RSA).b, {}, {}, &rep, nullptr)) return std::nullopt;  // none there
  R r(rep.body);
  Bytes nvPublic = r.sized();
  R np(nvPublic);
  np.u32(); np.u16(); np.u32(); np.sized();
  uint16_t size = np.u16();
  if (r.bad || np.bad || size == 0 || size > 4096) { if (why) *why = {"tpm_response", "the EK certificate's size is not readable", 0}; return std::nullopt; }
  Bytes cert;
  while (cert.size() < size) {
    uint16_t n = static_cast<uint16_t>(std::min<size_t>(512, size - cert.size()));
    Bytes params = W().u16(n).u16(static_cast<uint16_t>(cert.size())).b;
    if (!Run(ST_SESSIONS, CC_NV_Read, W().u32(RH_OWNER).u32(NV_EK_CERT_RSA).b, Auths({PasswordAuth()}), params, &rep, why)) return std::nullopt;
    Bytes p;
    if (!Params(rep.body, 0, &p, why)) return std::nullopt;
    R pr(p);
    Bytes chunk = pr.sized();
    if (pr.bad || chunk.empty()) { if (why) *why = {"tpm_response", "the EK certificate read came back empty", 0}; return std::nullopt; }
    cert.insert(cert.end(), chunk.begin(), chunk.end());
  }
  // The NV area may be longer than the DER certificate it holds.
  if (cert.size() > 4 && cert[0] == 0x30 && cert[1] == 0x82) cert.resize(std::min<size_t>(cert.size(), 4 + ((cert[2] << 8) | cert[3])));
  return cert;
}

std::optional<Bytes> EccPoint(const Bytes& tpm2b_public) {
  R r(tpm2b_public);
  Bytes area = r.sized();
  R a(area);
  uint16_t type = a.u16();
  a.u16(); a.u32(); a.sized();
  if (type != ALG_ECC) return std::nullopt;
  if (a.u16() != ALG_NULL) return std::nullopt;  // symmetric
  uint16_t scheme = a.u16();
  if (scheme != ALG_NULL) a.u16();
  if (a.u16() != CURVE_P256) return std::nullopt;
  if (a.u16() != ALG_NULL) return std::nullopt;  // kdf
  Bytes x = a.sized(), y = a.sized();
  if (a.bad || x.size() > 32 || y.size() > 32) return std::nullopt;
  Bytes out(65, 0);
  out[0] = 4;
  std::memcpy(out.data() + 33 - x.size(), x.data(), x.size());
  std::memcpy(out.data() + 65 - y.size(), y.data(), y.size());
  return out;
}

Bytes RawToDer(const Bytes& rs) {
  auto part = [](const uint8_t* v) {
    Bytes b(v, v + 32);
    while (b.size() > 1 && b[0] == 0) b.erase(b.begin());
    if (b[0] & 0x80) b.insert(b.begin(), 0);
    Bytes out{0x02, static_cast<uint8_t>(b.size())};
    out.insert(out.end(), b.begin(), b.end());
    return out;
  };
  Bytes r = part(rs.data()), s = part(rs.data() + 32);
  Bytes out{0x30, static_cast<uint8_t>(r.size() + s.size())};
  out.insert(out.end(), r.begin(), r.end());
  out.insert(out.end(), s.begin(), s.end());
  return out;
}

// ---- the two steps ----
namespace {
Bytes Pack2(const Created& c) { return W().sized(c.private_blob).sized(c.public_area).b; }
std::optional<Created> Unpack2(const Bytes& v) {
  R r(v);
  Bytes a = r.sized(), b = r.sized();
  if (r.bad) return std::nullopt;
  return Created{a, b};
}
struct Held {  // a transient object this call loaded, flushed when it goes
  Device& d; uint32_t h;
  Held(Device& dev, uint32_t handle) : d(dev), h(handle) {}
  ~Held() { d.Flush(h); }
};
}  // namespace

std::optional<Enrolment> MakeEnrolment(Device& d, BlobStore& store, const std::string& label,
                                       const std::function<std::optional<Bytes>()>& ek_cert, Failure* why) {
  auto srk = d.Srk(why);
  if (!srk) return std::nullopt;
  Held hs(d, *srk);
  auto ak = d.CreateAk(*srk, why);
  if (!ak) return std::nullopt;
  Enrolment e;
  auto ek = d.Ek(&e.ek_public, why);
  if (!ek) return std::nullopt;
  d.Flush(*ek);
  // The certificate the manufacturer wrote into this TPM, else whatever else the
  // caller can get (Windows can fetch one a maker publishes for TPMs that carry none).
  auto cert = d.ReadEkCertificate(nullptr);
  if (!cert) cert = ek_cert();
  if (!cert || cert->empty()) {
    if (why) *why = {"no_ek_certificate", "this TPM has no endorsement key certificate the app can read, so its key cannot be shown to be a manufacturer's", 0};
    return std::nullopt;
  }
  e.ek_cert = *cert;
  e.ak_public = ak->public_area;
  if (!store.Put(label + ".ak", Pack2(*ak))) {
    if (why) *why = {"store", "the attestation key could not be kept for the next step", 0};
    return std::nullopt;
  }
  return e;
}

std::optional<Attested> Attest(Device& d, BlobStore& store, const std::string& label, const Bytes& challenge,
                               const Bytes& credential, const Bytes& secret, Failure* why) {
  auto akBlob = store.Get(label + ".ak");
  auto ak = akBlob ? Unpack2(*akBlob) : std::nullopt;
  if (!ak) { if (why) *why = {"no_enrolment", "no attestation key was made for this key: enrol first", 0}; return std::nullopt; }
  auto srk = d.Srk(why);
  if (!srk) return std::nullopt;
  Held hs(d, *srk);
  auto akh = d.Load(*srk, *ak, why);
  if (!akh) return std::nullopt;
  Held ha(d, *akh);
  Bytes ekpub;
  auto ek = d.Ek(&ekpub, why);
  if (!ek) return std::nullopt;
  // A TPM may hold as few as three transient objects (the reference
  // implementation does): the storage key, the attestation key and the key being made
  // are three, so the endorsement key goes as soon as it has opened the credential.
  auto released = d.ActivateCredential(*akh, *ek, credential, secret, why);
  d.Flush(*ek);
  if (!released) return std::nullopt;
  auto key = d.CreateAppKey(*srk, why);
  if (!key) return std::nullopt;
  auto kh = d.Load(*srk, *key, why);
  if (!kh) return std::nullopt;
  Held hk(d, *kh);
  auto cert = d.Certify(*kh, *akh, CertifyExtraData(challenge), why);
  if (!cert) return std::nullopt;
  auto point = EccPoint(key->public_area);
  if (!point) { if (why) *why = {"not_p256", "the TPM did not make a P-256 key", 0}; return std::nullopt; }
  // The new key replaces any held, and only once everything above has held.
  if (!store.Put(label + ".key", Pack2(*key))) { if (why) *why = {"store", "the key could not be kept", 0}; return std::nullopt; }
  return Attested{*point, key->public_area, cert->attest, cert->signature, *released};
}

std::optional<Bytes> PublicPointOf(BlobStore& store, const std::string& label) {
  auto b = store.Get(label + ".key");
  auto k = b ? Unpack2(*b) : std::nullopt;
  return k ? EccPoint(k->public_area) : std::nullopt;
}

std::optional<Bytes> SignDigest(Device& d, BlobStore& store, const std::string& label, const Bytes& digest, Failure* why) {
  auto b = store.Get(label + ".key");
  auto k = b ? Unpack2(*b) : std::nullopt;
  if (!k) { if (why) *why = {"no_key", "no key is held under this name", 0}; return std::nullopt; }
  auto srk = d.Srk(why);
  if (!srk) return std::nullopt;
  Held hs(d, *srk);
  auto kh = d.Load(*srk, *k, why);
  if (!kh) return std::nullopt;
  Held hk(d, *kh);
  auto rs = d.Sign(*kh, digest, why);
  if (!rs) return std::nullopt;
  return RawToDer(*rs);
}

}  // namespace tpm2
