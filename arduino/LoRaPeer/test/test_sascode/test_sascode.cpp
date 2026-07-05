// test_sascode.cpp — suite Unity para SasCode (env:native)
// Corre con: pio test -e native --filter test_sascode
//
// El SHA-256 real (mbedtls) no esta en nativo; se inyecta un hash fake
// determinista. Verifica: 6 digitos, simetria (A y B obtienen lo mismo),
// sensibilidad al secreto y a las pubkeys, y el fingerprint.

#include <unity.h>
#include "SasCode.h"
#include <string>

void setUp(void) {}
void tearDown(void) {}

// Hash fake determinista de 8 bytes. Depende de TODO el mensaje. No es cripto.
static std::string fakeHash(const std::string &msg) {
  std::string d(8, 0);
  uint32_t acc = 2166136261u;  // FNV-ish para mezclar
  for (unsigned char c : msg) { acc ^= c; acc *= 16777619u; d[acc % 8] ^= (char)(c + (acc & 0xFF)); }
  for (int i = 0; i < 4; i++) d[i] ^= (char)((acc >> (i * 8)) & 0xFF);
  return d;
}

static SasCode::HashFn H = fakeHash;

static std::string pub(char fill) { return std::string(32, fill); }

// ==================== formato ====================

void test_sas_is_6_digits(void) {
  std::string s = SasCode::sas6("shared-secret-xyz", pub('A'), pub('B'), H);
  TEST_ASSERT_EQUAL_UINT32(6, s.size());
  for (char c : s) TEST_ASSERT_TRUE(c >= '0' && c <= '9');
}

// ==================== simetria (clave del anti-MITM) ====================

void test_sas_symmetric_in_pub_order(void) {
  // A y B pasan las pubkeys en orden opuesto y deben coincidir.
  std::string sAB = SasCode::sas6("SS", pub('A'), pub('B'), H);
  std::string sBA = SasCode::sas6("SS", pub('B'), pub('A'), H);
  TEST_ASSERT_EQUAL_STRING(sAB.c_str(), sBA.c_str());
}

// ==================== sensibilidad ====================

void test_sas_changes_with_shared_secret(void) {
  // Un MITM produce shared secrets distintos en cada lado -> SAS distinto.
  std::string s1 = SasCode::sas6("secreto-lado-1", pub('A'), pub('B'), H);
  std::string s2 = SasCode::sas6("secreto-lado-2", pub('A'), pub('B'), H);
  TEST_ASSERT_TRUE(s1 != s2);
}

void test_sas_changes_with_pubkeys(void) {
  std::string s1 = SasCode::sas6("SS", pub('A'), pub('B'), H);
  std::string s2 = SasCode::sas6("SS", pub('A'), pub('C'), H);
  TEST_ASSERT_TRUE(s1 != s2);
}

// ==================== fingerprint ====================

void test_fingerprint_is_8_hex(void) {
  std::string f = SasCode::fingerprint(pub('A'), H);
  TEST_ASSERT_EQUAL_UINT32(8, f.size());
  for (char c : f) {
    bool okc = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    TEST_ASSERT_TRUE(okc);
  }
}

void test_fingerprint_differs_by_pubkey(void) {
  std::string fa = SasCode::fingerprint(pub('A'), H);
  std::string fb = SasCode::fingerprint(pub('B'), H);
  TEST_ASSERT_TRUE(fa != fb);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_sas_is_6_digits);
  RUN_TEST(test_sas_symmetric_in_pub_order);
  RUN_TEST(test_sas_changes_with_shared_secret);
  RUN_TEST(test_sas_changes_with_pubkeys);
  RUN_TEST(test_fingerprint_is_8_hex);
  RUN_TEST(test_fingerprint_differs_by_pubkey);
  UNITY_END();
  return 0;
}
