// test_authgate.cpp — suite Unity para AuthGate (env:native)
// Corre con: pio test -e native --filter test_authgate
//
// El HMAC real (mbedtls) no esta en nativo; se inyecta un fake determinista
// que igual verifica toda la logica de la maquina de estados: desafio, token,
// enforcement de comandos y rechazos.

#include <unity.h>
#include "AuthGate.h"
#include <string>

void setUp(void) {}
void tearDown(void) {}

// HMAC fake determinista: digest de 8 bytes = XOR de bytes de key y msg
// intercalados + longitud, para que cambie con key y con msg. NO es cripto,
// solo determinismo suficiente para testear el flujo.
static std::string fakeHmac(const std::string &key, const std::string &msg) {
  std::string d(8, 0);
  for (size_t i = 0; i < key.size(); i++) d[i % 8] ^= key[i];
  for (size_t i = 0; i < msg.size(); i++) d[(i + 3) % 8] ^= (char)(msg[i] + 1);
  d[7] ^= (char)(key.size() * 7 + msg.size());
  return d;
}

static AuthGate makeGate() { return AuthGate(fakeHmac); }

// El cliente honesto calcula el mismo HMAC que la placa sobre los bytes crudos
// del nonce. Replica toHex(fakeHmac(secret, fromHex(nonceHex))).
static std::string clientMac(const std::string &secret, const std::string &nonceHex) {
  // fromHex del nonce (8 hex -> 4 bytes)
  std::string raw;
  auto hv = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
  };
  for (size_t i = 0; i + 1 < nonceHex.size(); i += 2)
    raw.push_back((char)((hv(nonceHex[i]) << 4) | hv(nonceHex[i + 1])));
  std::string dig = fakeHmac(secret, raw);
  static const char *H = "0123456789abcdef";
  std::string out;
  for (unsigned char b : dig) { out.push_back(H[(b >> 4) & 0xF]); out.push_back(H[b & 0xF]); }
  return out;
}

// ==================== nonce ====================

void test_makeNonce_is_8_hex(void) {
  std::string n = AuthGate::makeNonce(0xABCD1234);
  TEST_ASSERT_EQUAL_UINT32(8, n.size());
  TEST_ASSERT_EQUAL_STRING("abcd1234", n.c_str());
}

void test_makeNonce_zero(void) {
  TEST_ASSERT_EQUAL_STRING("00000000", AuthGate::makeNonce(0).c_str());
}

// ==================== handshake feliz ====================

void test_valid_response_issues_token(void) {
  AuthGate g = makeGate();
  std::string secret = "0123456789abcdef";  // 16 bytes
  std::string nonce = AuthGate::makeNonce(0x11223344);
  g.beginChallenge(nonce);
  std::string tok = g.verifyResponse(secret, clientMac(secret, nonce));
  TEST_ASSERT_TRUE(g.isAuthed());
  TEST_ASSERT_EQUAL_UINT32(8, tok.size());
  TEST_ASSERT_EQUAL_STRING(tok.c_str(), g.token().c_str());
}

// ==================== rechazos ====================

void test_wrong_mac_rejected(void) {
  AuthGate g = makeGate();
  g.beginChallenge(AuthGate::makeNonce(1));
  std::string tok = g.verifyResponse("secretA", "deadbeefdeadbeef");
  TEST_ASSERT_EQUAL_STRING("", tok.c_str());
  TEST_ASSERT_FALSE(g.isAuthed());
}

void test_wrong_secret_rejected(void) {
  AuthGate g = makeGate();
  std::string nonce = AuthGate::makeNonce(7);
  g.beginChallenge(nonce);
  // Cliente usa un secreto distinto al que verificara la placa.
  std::string mac = clientMac("secretCLIENTE", nonce);
  std::string tok = g.verifyResponse("secretPLACA", mac);
  TEST_ASSERT_EQUAL_STRING("", tok.c_str());
  TEST_ASSERT_FALSE(g.isAuthed());
}

void test_verify_without_challenge_fails(void) {
  AuthGate g = makeGate();
  std::string tok = g.verifyResponse("s", "0000");
  TEST_ASSERT_EQUAL_STRING("", tok.c_str());
  TEST_ASSERT_FALSE(g.isAuthed());
}

// ==================== enforcement de comandos ====================

void test_command_requires_valid_token(void) {
  AuthGate g = makeGate();
  std::string secret = "keykeykeykeykey0";
  std::string nonce = AuthGate::makeNonce(0x55);
  g.beginChallenge(nonce);
  std::string tok = g.verifyResponse(secret, clientMac(secret, nonce));

  std::string payload;
  TEST_ASSERT_TRUE(g.checkCommand(tok + "|SEND:1234:hola", payload));
  TEST_ASSERT_EQUAL_STRING("SEND:1234:hola", payload.c_str());
}

void test_command_wrong_token_rejected(void) {
  AuthGate g = makeGate();
  std::string secret = "keykeykeykeykey0";
  std::string nonce = AuthGate::makeNonce(0x55);
  g.beginChallenge(nonce);
  g.verifyResponse(secret, clientMac(secret, nonce));

  std::string payload;
  TEST_ASSERT_FALSE(g.checkCommand("00000000|SEND:x", payload));
}

void test_command_without_session_rejected(void) {
  AuthGate g = makeGate();
  std::string payload;
  TEST_ASSERT_FALSE(g.checkCommand("anytoken|SEND:x", payload));
}

void test_command_without_separator_rejected(void) {
  AuthGate g = makeGate();
  std::string secret = "keykeykeykeykey0";
  std::string nonce = AuthGate::makeNonce(3);
  g.beginChallenge(nonce);
  std::string tok = g.verifyResponse(secret, clientMac(secret, nonce));
  std::string payload;
  TEST_ASSERT_FALSE(g.checkCommand(tok, payload));  // sin '|'
}

void test_payload_may_contain_separator(void) {
  AuthGate g = makeGate();
  std::string secret = "keykeykeykeykey0";
  std::string nonce = AuthGate::makeNonce(9);
  g.beginChallenge(nonce);
  std::string tok = g.verifyResponse(secret, clientMac(secret, nonce));
  std::string payload;
  // Solo el primer '|' separa; el resto es parte del comando (p. ej. texto).
  TEST_ASSERT_TRUE(g.checkCommand(tok + "|SEND:1|con|pipes", payload));
  TEST_ASSERT_EQUAL_STRING("SEND:1|con|pipes", payload.c_str());
}

// ==================== handshake exento ====================

void test_handshake_commands_detected(void) {
  TEST_ASSERT_TRUE(AuthGate::isHandshakeCommand("NONCE"));
  TEST_ASSERT_TRUE(AuthGate::isHandshakeCommand("AUTH:deadbeef"));
  TEST_ASSERT_FALSE(AuthGate::isHandshakeCommand("SEND:1:hola"));
  TEST_ASSERT_FALSE(AuthGate::isHandshakeCommand("NONCEX"));
}

// ==================== reset / re-challenge ====================

void test_reset_clears_session(void) {
  AuthGate g = makeGate();
  std::string secret = "keykeykeykeykey0";
  std::string nonce = AuthGate::makeNonce(0x1);
  g.beginChallenge(nonce);
  std::string tok = g.verifyResponse(secret, clientMac(secret, nonce));
  g.reset();
  TEST_ASSERT_FALSE(g.isAuthed());
  std::string payload;
  TEST_ASSERT_FALSE(g.checkCommand(tok + "|SEND:x", payload));
}

void test_new_challenge_invalidates_old_token(void) {
  AuthGate g = makeGate();
  std::string secret = "keykeykeykeykey0";
  std::string n1 = AuthGate::makeNonce(0x1);
  g.beginChallenge(n1);
  std::string oldTok = g.verifyResponse(secret, clientMac(secret, n1));
  // Nueva conexion -> nuevo desafio, sin verificar aun.
  std::string n2 = AuthGate::makeNonce(0x2);
  g.beginChallenge(n2);
  TEST_ASSERT_FALSE(g.isAuthed());
  std::string payload;
  TEST_ASSERT_FALSE(g.checkCommand(oldTok + "|SEND:x", payload));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_makeNonce_is_8_hex);
  RUN_TEST(test_makeNonce_zero);
  RUN_TEST(test_valid_response_issues_token);
  RUN_TEST(test_wrong_mac_rejected);
  RUN_TEST(test_wrong_secret_rejected);
  RUN_TEST(test_verify_without_challenge_fails);
  RUN_TEST(test_command_requires_valid_token);
  RUN_TEST(test_command_wrong_token_rejected);
  RUN_TEST(test_command_without_session_rejected);
  RUN_TEST(test_command_without_separator_rejected);
  RUN_TEST(test_payload_may_contain_separator);
  RUN_TEST(test_handshake_commands_detected);
  RUN_TEST(test_reset_clears_session);
  RUN_TEST(test_new_challenge_invalidates_old_token);
  return UNITY_END();
}
