#include <unity.h>
#include "WifiCommand.h"

void setUp(void) {}
void tearDown(void) {}

// Caso 1: SSID y pass simples.
void test_simple_ssid_and_pass(void) {
  WifiCredentials r = parseSetWifi("SETWIFI:Pixel:secret");
  TEST_ASSERT_TRUE(r.valid);
  TEST_ASSERT_EQUAL_STRING("Pixel", r.ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("secret", r.pass.c_str());
}

// Caso 2: Pass con ':' embebidos — se conservan completos.
void test_pass_with_colons(void) {
  WifiCredentials r = parseSetWifi("SETWIFI:Pixel:pa:ss:wd");
  TEST_ASSERT_TRUE(r.valid);
  TEST_ASSERT_EQUAL_STRING("Pixel", r.ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("pa:ss:wd", r.pass.c_str());
}

// Caso 3: Pass vacia => red abierta, valida.
void test_open_network_empty_pass(void) {
  WifiCredentials r = parseSetWifi("SETWIFI:MiCasa:");
  TEST_ASSERT_TRUE(r.valid);
  TEST_ASSERT_EQUAL_STRING("MiCasa", r.ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("", r.pass.c_str());
}

// Caso 4: SSID con espacios => trim aplicado.
void test_ssid_trim(void) {
  WifiCredentials r = parseSetWifi("SETWIFI: Pixel :secret");
  TEST_ASSERT_TRUE(r.valid);
  TEST_ASSERT_EQUAL_STRING("Pixel", r.ssid.c_str());
}

// Caso 5: SSID vacio => invalido.
void test_empty_ssid_invalid(void) {
  WifiCredentials r = parseSetWifi("SETWIFI::secret");
  TEST_ASSERT_FALSE(r.valid);
}

// Caso 6: Sin separador ssid/pass => invalido.
void test_missing_separator_invalid(void) {
  WifiCredentials r = parseSetWifi("SETWIFI:SoloSsid");
  TEST_ASSERT_FALSE(r.valid);
}

// Caso 7: Prefijo incorrecto => invalido.
void test_wrong_prefix_invalid(void) {
  WifiCredentials r = parseSetWifi("HELLO:a:b");
  TEST_ASSERT_FALSE(r.valid);
}

// Caso 8: Linea vacia => invalido.
void test_empty_line_invalid(void) {
  WifiCredentials r = parseSetWifi("");
  TEST_ASSERT_FALSE(r.valid);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_simple_ssid_and_pass);
  RUN_TEST(test_pass_with_colons);
  RUN_TEST(test_open_network_empty_pass);
  RUN_TEST(test_ssid_trim);
  RUN_TEST(test_empty_ssid_invalid);
  RUN_TEST(test_missing_separator_invalid);
  RUN_TEST(test_wrong_prefix_invalid);
  RUN_TEST(test_empty_line_invalid);
  return UNITY_END();
}
