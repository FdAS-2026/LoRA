#include "AuthGate.h"

namespace {

const char *kHex = "0123456789abcdef";

std::string toHex(const std::string &raw) {
  std::string out;
  out.reserve(raw.size() * 2);
  for (unsigned char b : raw) {
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Decodifica hex a bytes crudos. Devuelve "" si el largo es impar o hay un
// caracter no-hex (entrada malformada del cliente).
std::string fromHex(const std::string &hex) {
  if (hex.size() % 2 != 0) return "";
  std::string out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = hexVal(hex[i]);
    int lo = hexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) return "";
    out.push_back((char)((hi << 4) | lo));
  }
  return out;
}

// Comparacion en tiempo constante: no cortocircuita segun el contenido, para
// no filtrar por timing cuantos caracteres del token/MAC coinciden.
bool constantTimeEquals(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); i++) {
    diff |= (unsigned char)(a[i] ^ b[i]);
  }
  return diff == 0;
}

}  // namespace

std::string AuthGate::makeNonce(uint32_t seed) {
  std::string out(8, '0');
  for (int i = 0; i < 8; i++) {
    out[7 - i] = kHex[(seed >> (i * 4)) & 0xF];
  }
  return out;
}

void AuthGate::beginChallenge(const std::string &nonceHex) {
  _nonce = nonceHex;
  _token.clear();
  _authed = false;
}

std::string AuthGate::verifyResponse(const std::string &secret,
                                     const std::string &clientMacHex) {
  if (_nonce.empty()) return "";  // no hay desafio activo

  // El nonce se autentica sobre sus bytes crudos (decodificados del hex).
  std::string nonceRaw = fromHex(_nonce);
  std::string expected = toHex(_hmac(secret, nonceRaw));

  std::string client = clientMacHex;
  // Normalizar a minusculas para comparar hex de forma robusta.
  for (char &c : client) {
    if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
  }
  if (!constantTimeEquals(expected, client)) {
    return "";
  }

  // Token de sesion = primeros 4 bytes (8 hex) de HMAC(secret, "T" + nonceRaw).
  std::string tokenFull = toHex(_hmac(secret, std::string("T") + nonceRaw));
  _token = tokenFull.substr(0, 8);
  _authed = true;
  return _token;
}

bool AuthGate::checkCommand(const std::string &input,
                            std::string &payloadOut) const {
  if (!_authed || _token.empty()) return false;
  size_t sep = input.find('|');
  if (sep == std::string::npos) return false;
  std::string tok = input.substr(0, sep);
  if (!constantTimeEquals(tok, _token)) return false;
  payloadOut = input.substr(sep + 1);
  return true;
}

bool AuthGate::isHandshakeCommand(const std::string &input) {
  return input == "NONCE" || input.rfind("AUTH:", 0) == 0;
}

void AuthGate::reset() {
  _nonce.clear();
  _token.clear();
  _authed = false;
}
