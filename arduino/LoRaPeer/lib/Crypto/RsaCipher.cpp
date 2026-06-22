#include "RsaCipher.h"

namespace {

uint32_t gcd(uint32_t a, uint32_t b) {
  while (b) {
    uint32_t t = a % b;
    a = b;
    b = t;
  }
  return a;
}

// Inverso modular de e mod m por euclides extendido. 0 si no existe.
uint32_t modInverse(uint32_t e, uint32_t m) {
  int64_t t = 0, newt = 1;
  int64_t r = (int64_t)m, newr = (int64_t)e;
  while (newr != 0) {
    int64_t q = r / newr;
    int64_t tmp = t - q * newt; t = newt; newt = tmp;
    tmp = r - q * newr; r = newr; newr = tmp;
  }
  if (r > 1) return 0;  // no invertible
  if (t < 0) t += m;
  return (uint32_t)t;
}

// base^exp mod n. n < 2^32, asi el producto cabe en uint64.
uint32_t modPow(uint64_t base, uint64_t exp, uint64_t n) {
  uint64_t result = 1 % n;
  base %= n;
  while (exp > 0) {
    if (exp & 1) result = (result * base) % n;
    base = (base * base) % n;
    exp >>= 1;
  }
  return (uint32_t)result;
}

void putU32(std::vector<uint8_t> &out, uint32_t v) {
  out.push_back(v & 0xFF);
  out.push_back((v >> 8) & 0xFF);
  out.push_back((v >> 16) & 0xFF);
  out.push_back((v >> 24) & 0xFF);
}

}  // namespace

RsaKeyPair RsaCipher::generate(uint32_t p, uint32_t q, uint32_t e) {
  RsaKeyPair kp{e, 0, 0, false};
  uint64_t n = (uint64_t)p * q;
  if (n <= 255 || n > 0xFFFFFFFFULL) return kp;  // n debe cubrir un byte y caber en 32 bits

  uint64_t phi = (uint64_t)(p - 1) * (q - 1);
  if (e < 2 || e >= phi) return kp;
  if (gcd(e, (uint32_t)phi) != 1) return kp;  // e debe ser coprimo con phi

  uint32_t d = modInverse(e, (uint32_t)phi);
  if (d == 0) return kp;

  kp.n = (uint32_t)n;
  kp.d = d;
  kp.valid = true;
  return kp;
}

std::vector<uint8_t> RsaCipher::encrypt(const std::string &plain, uint32_t e, uint32_t n) {
  std::vector<uint8_t> out;
  if (plain.empty() || n <= 255) return out;
  out.reserve(plain.size() * 4);
  for (unsigned char c : plain) {
    uint32_t cipher = modPow((uint64_t)c, e, n);
    putU32(out, cipher);
  }
  return out;
}

std::string RsaCipher::decrypt(const std::vector<uint8_t> &cipher, uint32_t d, uint32_t n) {
  std::string out;
  if (cipher.empty() || (cipher.size() % 4) != 0 || n <= 255) return out;
  out.reserve(cipher.size() / 4);
  for (size_t i = 0; i + 4 <= cipher.size(); i += 4) {
    uint32_t block = cipher[i] | (cipher[i + 1] << 8) | (cipher[i + 2] << 16) |
                     ((uint32_t)cipher[i + 3] << 24);
    uint32_t m = modPow((uint64_t)block, d, n);
    out.push_back((char)(unsigned char)(m & 0xFF));
  }
  return out;
}
