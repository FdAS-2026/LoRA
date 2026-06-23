#include <unity.h>
#include "MqttCodec.h"

void setUp(void) {}
void tearDown(void) {}

// ==================== inboxTopic ====================

// Caso 1: 4 hex sin padding necesario (4 digitos exactos).
void test_inboxTopic_full(void) {
  TEST_ASSERT_EQUAL_STRING("lorapeer/ABCD/inbox",
                            MqttCodec::inboxTopic(0xABCD).c_str());
}

// Caso 2: ID chico — relleno a la izquierda con ceros.
void test_inboxTopic_padding(void) {
  TEST_ASSERT_EQUAL_STRING("lorapeer/0001/inbox",
                            MqttCodec::inboxTopic(0x0001).c_str());
}

// Caso 3: Hex en MAYUSCULA, no minuscula.
void test_inboxTopic_uppercase(void) {
  TEST_ASSERT_EQUAL_STRING("lorapeer/00FF/inbox",
                            MqttCodec::inboxTopic(0x00FF).c_str());
}

// ==================== buildDataPayload ====================

// Caso 4: Header de 5 bytes — out[0..4] y retorno 5+blobLen.
// Formato: [srcHi][srcLo][type][msgIdHi][msgIdLo][blob...]
void test_build_header_bytes(void) {
  const uint8_t blob[] = {0xAA, 0xBB};
  uint8_t out[16];
  size_t n = MqttCodec::buildDataPayload(0x1234, 0x00, 0xABCD, blob, 2, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(7, n);
  TEST_ASSERT_EQUAL_HEX8(0x12, out[0]);
  TEST_ASSERT_EQUAL_HEX8(0x34, out[1]);
  TEST_ASSERT_EQUAL_HEX8(0x00, out[2]);
  TEST_ASSERT_EQUAL_HEX8(0xAB, out[3]);  // msgIdHi
  TEST_ASSERT_EQUAL_HEX8(0xCD, out[4]);  // msgIdLo
  TEST_ASSERT_EQUAL_HEX8(0xAA, out[5]);
  TEST_ASSERT_EQUAL_HEX8(0xBB, out[6]);
}

// Caso 5: Blob con 0x00 embebido — NO se trunca (anti-strlen).
void test_build_preserves_embedded_null(void) {
  const uint8_t blob[] = {0x00, 0xAA, 0x00};
  uint8_t out[16];
  size_t n = MqttCodec::buildDataPayload(0x0010, 0x02, 0x0001, blob, 3, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(8, n);  // 5 header + 3 blob
  TEST_ASSERT_EQUAL_UINT8_ARRAY(blob, out + 5, 3);
}

// Caso 6: outCap insuficiente — retorna 0 sin escribir.
void test_build_overflow_guard(void) {
  const uint8_t blob[] = {0x01, 0x02, 0x03};
  uint8_t out[4];  // 5+3=8 > 4
  size_t n = MqttCodec::buildDataPayload(0x0010, 0x01, 0x0000, blob, 3, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(0, n);
}

// ==================== parseDataHeader ====================

// Caso 7a: Payload de 2 bytes — rechazado (insuficiente para header de 5 bytes).
void test_parse_rejects_short_payload(void) {
  const uint8_t buf[] = {0x12, 0x34};  // solo 2 bytes
  uint16_t src; uint8_t type; uint16_t msgId; const uint8_t* blob; size_t blobLen;
  bool ok = MqttCodec::parseDataHeader(buf, 2, src, type, msgId, blob, blobLen);
  TEST_ASSERT_FALSE(ok);
}

// Caso 7b: Payload de 4 bytes — insuficiente; falta al menos el byte msgIdLo.
void test_parse_rejects_short(void) {
  const uint8_t buf[] = {0x12, 0x34, 0x00, 0xAB};  // 4 bytes, header de 5 requiere uno mas
  uint16_t src; uint8_t type; uint16_t msgId; const uint8_t* blob; size_t blobLen;
  bool ok = MqttCodec::parseDataHeader(buf, 4, src, type, msgId, blob, blobLen);
  TEST_ASSERT_FALSE(ok);
}

// Caso 8: Round-trip — build luego parse recupera src/type/msgId/blob identicos.
// El blob incluye un 0x00 interno para verificar que memcpy no hace strlen.
void test_roundtrip_build_parse(void) {
  const uint8_t originalBlob[] = {0xDE, 0xAD, 0x00, 0xEF};
  uint8_t buf[32];
  size_t written = MqttCodec::buildDataPayload(0x1234, 0x07, 0x0042,
                                               originalBlob, 4, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_UINT(9, written);  // 5 header + 4 blob

  uint16_t src; uint8_t type; uint16_t msgId; const uint8_t* blobPtr; size_t blobLen;
  bool ok = MqttCodec::parseDataHeader(buf, written, src, type, msgId, blobPtr, blobLen);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_EQUAL_HEX16(0x1234, src);
  TEST_ASSERT_EQUAL_HEX8(0x07, type);
  TEST_ASSERT_EQUAL_HEX16(0x0042, msgId);
  TEST_ASSERT_EQUAL_UINT(4, blobLen);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(originalBlob, blobPtr, 4);
}

// Caso 8b: blob==nullptr con blobLen>0 — debe retornar 5 (solo header) y NO contar el blob.
// Verifica que el contrato del header (.h: "si blob es nullptr retorna 5") se cumple.
void test_build_nullptr_blob_with_nonzero_len(void) {
  uint8_t out[16];
  size_t n = MqttCodec::buildDataPayload(0x0001, 0x00, 0x0002, nullptr, 10, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT_MESSAGE(5, n,
      "blob==nullptr debe normalizar blobLen a 0 y retornar solo el header (5)");
}

// Caso 9: ACK roundtrip — blob vacio, solo header de 5 bytes (cubre ACK-01).
// Verifica que un mensaje de tipo ACK/NACK sin carga util se serializa
// y parsea correctamente: n=5, blobLen=0, msgId recuperado intacto.
static const uint8_t TYPE_ACK = 4;

void test_ack_roundtrip(void) {
  uint8_t buf[8];
  size_t n = MqttCodec::buildDataPayload(0x1001, TYPE_ACK, 0xABCD,
                                         nullptr, 0, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_UINT(5, n);

  uint16_t src; uint8_t type; uint16_t msgId; const uint8_t* blob; size_t blobLen;
  bool ok = MqttCodec::parseDataHeader(buf, n, src, type, msgId, blob, blobLen);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_EQUAL_HEX16(0x1001, src);
  TEST_ASSERT_EQUAL_HEX8(TYPE_ACK, type);
  TEST_ASSERT_EQUAL_HEX16(0xABCD, msgId);
  TEST_ASSERT_EQUAL_UINT(0, blobLen);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_inboxTopic_full);
  RUN_TEST(test_inboxTopic_padding);
  RUN_TEST(test_inboxTopic_uppercase);
  RUN_TEST(test_build_header_bytes);
  RUN_TEST(test_build_preserves_embedded_null);
  RUN_TEST(test_build_overflow_guard);
  RUN_TEST(test_build_nullptr_blob_with_nonzero_len);
  RUN_TEST(test_parse_rejects_short_payload);
  RUN_TEST(test_parse_rejects_short);
  RUN_TEST(test_roundtrip_build_parse);
  RUN_TEST(test_ack_roundtrip);
  return UNITY_END();
}
