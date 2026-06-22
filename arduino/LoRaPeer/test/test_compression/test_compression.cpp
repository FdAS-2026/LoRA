#include <unity.h>
#include "HuffmanCodec.h"
#include <string>
#include <vector>

HuffmanCodec codec;

void setUp(void) {}
void tearDown(void) {}

// ==================== Roundtrip ====================

void test_roundtrip_simple(void) {
  std::string original = "Hola mundo LoRa";
  std::vector<uint8_t> encoded = codec.encode(original);
  std::string decoded = codec.decode(encoded);
  TEST_ASSERT_EQUAL_STRING(original.c_str(), decoded.c_str());
}

void test_roundtrip_empty(void) {
  std::string original = "";
  std::vector<uint8_t> encoded = codec.encode(original);
  std::string decoded = codec.decode(encoded);
  TEST_ASSERT_EQUAL_STRING("", decoded.c_str());
}

void test_roundtrip_single_symbol(void) {
  // Caso borde: un solo simbolo distinto repetido.
  std::string original = "aaaaaaaa";
  std::vector<uint8_t> encoded = codec.encode(original);
  std::string decoded = codec.decode(encoded);
  TEST_ASSERT_EQUAL_STRING(original.c_str(), decoded.c_str());
}

void test_roundtrip_single_char(void) {
  std::string original = "x";
  std::vector<uint8_t> encoded = codec.encode(original);
  std::string decoded = codec.decode(encoded);
  TEST_ASSERT_EQUAL_STRING(original.c_str(), decoded.c_str());
}

void test_roundtrip_binary_and_utf8_bytes(void) {
  // Bytes arbitrarios incluyendo altos (acentos UTF-8) y repeticiones.
  std::string original = "\xC3\xA1\xC3\xA9 \x01\x02\x7F repeticion repeticion repeticion";
  std::vector<uint8_t> encoded = codec.encode(original);
  std::string decoded = codec.decode(encoded);
  TEST_ASSERT_EQUAL_STRING(original.c_str(), decoded.c_str());
}

// ==================== Compresion efectiva ====================

void test_compresses_repetitive_text(void) {
  // Texto largo y repetitivo debe quedar mas chico que el original.
  std::string original;
  for (int i = 0; i < 30; i++) original += "el mensaje se repite ";
  std::vector<uint8_t> encoded = codec.encode(original);
  TEST_ASSERT_TRUE(encoded.size() < original.size());
}

void test_decode_invalid_returns_empty(void) {
  // Datos corruptos / incompletos no deben romper: retornan vacio.
  std::vector<uint8_t> garbage = {0x05, 0x00, 0x00};
  std::string decoded = codec.decode(garbage);
  TEST_ASSERT_EQUAL_STRING("", decoded.c_str());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_roundtrip_simple);
  RUN_TEST(test_roundtrip_empty);
  RUN_TEST(test_roundtrip_single_symbol);
  RUN_TEST(test_roundtrip_single_char);
  RUN_TEST(test_roundtrip_binary_and_utf8_bytes);
  RUN_TEST(test_compresses_repetitive_text);
  RUN_TEST(test_decode_invalid_returns_empty);
  return UNITY_END();
}
