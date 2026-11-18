// A command line over tpm2.cpp for the test that runs it against a software TPM
// (identity-agent-core/secureenclave/testdata/tpmsim/driver). It speaks one line
// per command on stdin and answers one line, byte strings in hex:
//
//   enrol  <label> <ek certificate>            -> ek_public ek_cert ak_public
//   attest <label> <challenge> <credential> <secret>
//                                              -> point key_public certify_info certify_signature credential_secret
//   point  <label>                             -> point
//   sign   <label> <digest>                    -> der
//
// The TPM is a unix socket (argv[1]); the keys it makes are kept in memory for the life of the process.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>

#include "../tpm2.h"

using tpm2::Bytes;

static Bytes FromHex(const std::string& s) {
  Bytes o;
  for (size_t i = 0; i + 1 < s.size(); i += 2) o.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
  return o;
}
static std::string Hex(const Bytes& b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (auto v : b) { s += d[v >> 4]; s += d[v & 15]; }
  return s.empty() ? "-" : s;
}

struct Memory : tpm2::BlobStore {
  std::map<std::string, Bytes> m;
  bool Put(const std::string& n, const Bytes& v) override { m[n] = v; return true; }
  std::optional<Bytes> Get(const std::string& n) override {
    auto i = m.find(n);
    if (i == m.end()) return std::nullopt;
    return i->second;
  }
};

static bool ReadAll(int fd, uint8_t* p, size_t n) {
  while (n) { ssize_t r = read(fd, p, n); if (r <= 0) return false; p += r; n -= r; }
  return true;
}

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  snprintf(a.sun_path, sizeof a.sun_path, "%s", argv[1]);
  if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) { perror("connect"); return 1; }
  tpm2::Device dev([&](const Bytes& cmd, Bytes* resp) {
    size_t off = 0;
    while (off < cmd.size()) { ssize_t w = write(fd, cmd.data() + off, cmd.size() - off); if (w <= 0) return false; off += w; }
    uint8_t head[10];
    if (!ReadAll(fd, head, 10)) return false;
    uint32_t size = (head[2] << 24) | (head[3] << 16) | (head[4] << 8) | head[5];
    resp->assign(head, head + 10);
    resp->resize(size);
    return size < 10 || ReadAll(fd, resp->data() + 10, size - 10);
  });
  Memory store;
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream in(line);
    std::string cmd, label;
    in >> cmd >> label;
    tpm2::Failure why;
    auto fail = [&] { std::cout << "ERR " << why.code << " " << why.message << std::endl; };
    if (cmd == "enrol") {
      std::string cert;
      in >> cert;
      auto e = tpm2::MakeEnrolment(dev, store, label, [&]() -> std::optional<Bytes> { return FromHex(cert); }, &why);
      if (!e) fail(); else std::cout << "OK " << Hex(e->ek_public) << " " << Hex(e->ek_cert) << " " << Hex(e->ak_public) << std::endl;
    } else if (cmd == "attest") {
      std::string ch, cr, se;
      in >> ch >> cr >> se;
      auto r = tpm2::Attest(dev, store, label, FromHex(ch), FromHex(cr), FromHex(se), &why);
      if (!r) fail();
      else std::cout << "OK " << Hex(r->point) << " " << Hex(r->key_public) << " " << Hex(r->certify_info) << " " << Hex(r->certify_signature) << " " << Hex(r->credential_secret) << std::endl;
    } else if (cmd == "point") {
      auto p = tpm2::PublicPointOf(store, label);
      if (!p) { why = {"no_key", "none", 0}; fail(); } else std::cout << "OK " << Hex(*p) << std::endl;
    } else if (cmd == "sign") {
      std::string dg;
      in >> dg;
      auto s = tpm2::SignDigest(dev, store, label, FromHex(dg), &why);
      if (!s) fail(); else std::cout << "OK " << Hex(*s) << std::endl;
    } else {
      std::cout << "ERR bad_command " << cmd << std::endl;
    }
  }
  return 0;
}
