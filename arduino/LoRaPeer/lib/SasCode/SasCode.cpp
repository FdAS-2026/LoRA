#include "SasCode.h"

namespace {

const char *kHex = "0123456789abcdef";

std::string toHex(const std::string &raw, size_t nBytes) {
  std::string out;
  for (size_t i = 0; i < nBytes && i < raw.size(); i++) {
    unsigned char b = (unsigned char)raw[i];
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

// uint32 big-endian de los primeros 4 bytes del digest.
uint32_t first4(const std::string &digest) {
  uint32_t v = 0;
  for (int i = 0; i < 4 && i < (int)digest.size(); i++) {
    v = (v << 8) | (unsigned char)digest[i];
  }
  return v;
}

}  // namespace

std::string SasCode::sas6(const std::string &sharedSecret,
                          const std::string &pubA, const std::string &pubB,
                          const HashFn &hash) {
  // Orden canonico: menor||mayor por comparacion lexicografica de bytes.
  const std::string &lo = (pubA <= pubB) ? pubA : pubB;
  const std::string &hi = (pubA <= pubB) ? pubB : pubA;

  std::string msg = sharedSecret;
  msg += lo;
  msg += hi;

  uint32_t v = first4(hash(msg)) % 1000000u;

  // Zero-pad a 6 digitos.
  std::string out(6, '0');
  for (int i = 5; i >= 0; i--) {
    out[i] = (char)('0' + (v % 10));
    v /= 10;
  }
  return out;
}

std::string SasCode::fingerprint(const std::string &pub, const HashFn &hash) {
  return toHex(hash(pub), 4);
}
