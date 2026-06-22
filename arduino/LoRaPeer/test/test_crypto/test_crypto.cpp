#include <unity.h>
#include "RsaCipher.h"
#include <string>
#include <vector>

void setUp(void) {}
void tearDown(void) {}

// Primos de demostracion. n = 64507 > 255, asi cada byte se cifra unicamente.
static const uint32_t P = 251;
static const uint32_t Q = 257;
static const uint32_t E = 17;

// ==================== Generacion de claves ====================

void test_keypair_is_valid(void) {
  RsaKeyPair kp = RsaCipher::generate(P, Q, E);
  TEST_ASSERT_TRUE(kp.valid);
  TEST_ASSERT_EQUAL_UINT32(P * Q, kp.n);
  TEST_ASSERT_EQUAL_UINT32(E, kp.e);
  // e * d ≡ 1 (mod phi), con phi = (p-1)(q-1).
  uint64_t phi = (uint64_t)(P - 1) * (Q - 1);
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)(((uint64_t)kp.e * kp.d) % phi));
}

void test_keypair_invalid_when_e_not_coprime(void) {
  // e = 2 no es coprimo con phi (par) => generacion invalida.
  RsaKeyPair kp = RsaCipher::generate(P, Q, 2);
  TEST_ASSERT_FALSE(kp.valid);
}

// ==================== Cifrado / descifrado ====================

void test_roundtrip(void) {
  RsaKeyPair kp = RsaCipher::generate(P, Q, E);
  std::string plain = "Mensaje secreto para el broker";
  std::vector<uint8_t> cipher = RsaCipher::encrypt(plain, kp.e, kp.n);
  std::string decrypted = RsaCipher::decrypt(cipher, kp.d, kp.n);
  TEST_ASSERT_EQUAL_STRING(plain.c_str(), decrypted.c_str());
}

void test_ciphertext_differs_from_plaintext(void) {
  RsaKeyPair kp = RsaCipher::generate(P, Q, E);
  std::string plain = "hola";
  std::vector<uint8_t> cipher = RsaCipher::encrypt(plain, kp.e, kp.n);
  std::string asText(cipher.begin(), cipher.end());
  TEST_ASSERT_TRUE(asText != plain);
}

void test_only_private_key_decrypts(void) {
  // Cifrado con la publica de un par; descifrar con OTRA privada no recupera el texto.
  RsaKeyPair kp = RsaCipher::generate(P, Q, E);
  RsaKeyPair other = RsaCipher::generate(263, 269, E);  // distinto modulo/clave
  std::string plain = "solo la privada correcta";
  std::vector<uint8_t> cipher = RsaCipher::encrypt(plain, kp.e, kp.n);
  std::string wrong = RsaCipher::decrypt(cipher, other.d, other.n);
  TEST_ASSERT_TRUE(wrong != plain);
}

void test_roundtrip_empty(void) {
  RsaKeyPair kp = RsaCipher::generate(P, Q, E);
  std::vector<uint8_t> cipher = RsaCipher::encrypt("", kp.e, kp.n);
  std::string decrypted = RsaCipher::decrypt(cipher, kp.d, kp.n);
  TEST_ASSERT_EQUAL_STRING("", decrypted.c_str());
}

void test_roundtrip_high_bytes(void) {
  RsaKeyPair kp = RsaCipher::generate(P, Q, E);
  // Bytes con NUL embebido: construido con largo explicito (el literal cortaria en \x00).
  const unsigned char raw[] = {0x00, 0xFF, 0x80, 0x7F, ' ', 'a', 'b', 0xC3, 0xB1};
  std::string plain(reinterpret_cast<const char *>(raw), sizeof(raw));
  std::vector<uint8_t> cipher = RsaCipher::encrypt(plain, kp.e, kp.n);
  std::string decrypted = RsaCipher::decrypt(cipher, kp.d, kp.n);
  TEST_ASSERT_EQUAL_INT(plain.size(), decrypted.size());
  TEST_ASSERT_EQUAL_MEMORY(plain.data(), decrypted.data(), plain.size());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_keypair_is_valid);
  RUN_TEST(test_keypair_invalid_when_e_not_coprime);
  RUN_TEST(test_roundtrip);
  RUN_TEST(test_ciphertext_differs_from_plaintext);
  RUN_TEST(test_only_private_key_decrypts);
  RUN_TEST(test_roundtrip_empty);
  RUN_TEST(test_roundtrip_high_bytes);
  return UNITY_END();
}
