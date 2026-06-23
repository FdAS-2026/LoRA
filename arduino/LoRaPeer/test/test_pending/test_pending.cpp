// test_pending.cpp — suite Unity para InflightTable (env:native)
// Corre con: pio test -e native --filter test_pending

#include <unity.h>
#include "InflightTable.h"

void setUp(void) {}
void tearDown(void) {}

// ==================== add: capacidad y slot retornado ====================

// Caso 1: llenar la tabla hasta CAP=6 — cada add devuelve un idx distinto en [0,5].
void test_add_fills_all_slots(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01, 0x02};
    int idxs[InflightTable::CAP];
    for (int i = 0; i < InflightTable::CAP; i++) {
        idxs[i] = t.add((uint16_t)(0x0100 + i), 0xAAAA, blob, sizeof(blob), 1000);
        TEST_ASSERT_TRUE_MESSAGE(idxs[i] >= 0 && idxs[i] < InflightTable::CAP,
                                 "add debe retornar un idx valido");
    }
    // Verificar que todos los idx son distintos
    for (int i = 0; i < InflightTable::CAP; i++) {
        for (int j = i + 1; j < InflightTable::CAP; j++) {
            TEST_ASSERT_NOT_EQUAL_MESSAGE(idxs[i], idxs[j],
                                         "cada slot debe ser unico");
        }
    }
}

// Caso 2: el 7mo add con la tabla llena devuelve -1 (sin pisar entradas).
void test_add_returns_minus1_when_full(void) {
    InflightTable t;
    const uint8_t blob[] = {0xAA};
    for (int i = 0; i < InflightTable::CAP; i++) {
        t.add((uint16_t)(0x0200 + i), 0xBBBB, blob, sizeof(blob), 1000);
    }
    int extra = t.add(0x9999, 0xCCCC, blob, sizeof(blob), 1000);
    TEST_ASSERT_EQUAL_INT(-1, extra);
}

// ==================== find ====================

// Caso 3: find devuelve el idx correcto para un msgId registrado.
void test_find_returns_correct_idx(void) {
    InflightTable t;
    const uint8_t blob[] = {0x55};
    int idx = t.add(0x1234, 0xAAAA, blob, sizeof(blob), 500);
    TEST_ASSERT_TRUE(idx >= 0);
    TEST_ASSERT_EQUAL_INT(idx, t.find(0x1234));
}

// Caso 4: find de un msgId inexistente devuelve -1.
void test_find_returns_minus1_for_unknown(void) {
    InflightTable t;
    TEST_ASSERT_EQUAL_INT(-1, t.find(0xDEAD));
}

// ==================== clearByMsgId / reuso de slot ====================

// Caso 5: clearByMsgId libera el slot (stage vuelve a EMPTY)
// y un add posterior puede reutilizarlo.
void test_clear_and_reuse(void) {
    InflightTable t;
    const uint8_t blob[] = {0x11};
    // Llenar la tabla
    for (int i = 0; i < InflightTable::CAP; i++) {
        t.add((uint16_t)(0x0300 + i), 0x1111, blob, sizeof(blob), 1000);
    }
    // Liberar el que tiene msgId 0x0301
    t.clearByMsgId(0x0301);
    // Ahora hay un slot libre — el 7mo add debe tener exito
    int idx = t.add(0x0399, 0x2222, blob, sizeof(blob), 2000);
    TEST_ASSERT_TRUE_MESSAGE(idx >= 0, "debe poder agregar tras limpiar un slot");
    TEST_ASSERT_EQUAL_INT(idx, t.find(0x0399));
}

// Caso 6: tras clearByMsgId, find(msgId_liberado) devuelve -1.
void test_find_after_clear_returns_minus1(void) {
    InflightTable t;
    const uint8_t blob[] = {0x22};
    t.add(0xAAAA, 0x1111, blob, sizeof(blob), 1000);
    t.clearByMsgId(0xAAAA);
    TEST_ASSERT_EQUAL_INT(-1, t.find(0xAAAA));
}

// ==================== due: transiciones de timeout ====================

// Caso 7: stage LORA, elapsed=2999ms, timeout 3000ms → DUE_NONE.
void test_due_lora_before_timeout(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01};
    int idx = t.add(0x0001, 0x0002, blob, sizeof(blob), /*now=*/1000);
    TEST_ASSERT_TRUE(idx >= 0);
    TEST_ASSERT_EQUAL(InflightTable::LORA, t.stage(idx));
    // now = 1000 + 2999 = 3999
    InflightTable::DueAction action = t.due(idx, 3999, 3000, 5000);
    TEST_ASSERT_EQUAL(InflightTable::DUE_NONE, action);
}

// Caso 8: stage LORA, elapsed=3000ms exactos → DUE_FALLBACK.
void test_due_lora_at_timeout(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01};
    int idx = t.add(0x0002, 0x0003, blob, sizeof(blob), /*now=*/1000);
    // now = 1000 + 3000 = 4000
    InflightTable::DueAction action = t.due(idx, 4000, 3000, 5000);
    TEST_ASSERT_EQUAL(InflightTable::DUE_FALLBACK, action);
}

// Caso 9: promoteToMqtt cambia stage a MQTT y resetea ts;
// due(MQTT, elapsed=4999ms) → DUE_NONE.
void test_due_mqtt_before_timeout(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01};
    int idx = t.add(0x0003, 0x0004, blob, sizeof(blob), /*now=*/1000);
    t.promoteToMqtt(idx, /*now=*/5000);
    TEST_ASSERT_EQUAL(InflightTable::MQTT, t.stage(idx));
    // now = 5000 + 4999 = 9999
    InflightTable::DueAction action = t.due(idx, 9999, 3000, 5000);
    TEST_ASSERT_EQUAL(InflightTable::DUE_NONE, action);
}

// Caso 10: stage MQTT, elapsed=5000ms exactos → DUE_FAIL.
void test_due_mqtt_at_timeout(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01};
    int idx = t.add(0x0004, 0x0005, blob, sizeof(blob), /*now=*/1000);
    t.promoteToMqtt(idx, /*now=*/5000);
    // now = 5000 + 5000 = 10000
    InflightTable::DueAction action = t.due(idx, 10000, 3000, 5000);
    TEST_ASSERT_EQUAL(InflightTable::DUE_FAIL, action);
}

// ==================== wrap-safe: overflow de uint32_t ====================

// Caso 11: ts=0xFFFFFF00, now=0x00000064 (now < ts por overflow).
// Delta real = 256 + 100 = 356ms < 3000ms → DUE_NONE (resta unsigned).
void test_due_wrap_safe_below_timeout(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01};
    uint32_t ts  = 0xFFFFFF00u;
    uint32_t now = 0x00000064u;  // now < ts en aritmética normal, pero overflow real ~356ms
    int idx = t.add(0x0005, 0x0006, blob, sizeof(blob), ts);
    // Verificar que la resta unsigned da ~356ms y no dispara DUE_FALLBACK (3000ms)
    InflightTable::DueAction action = t.due(idx, now, 3000, 5000);
    TEST_ASSERT_EQUAL(InflightTable::DUE_NONE, action);
}

// ==================== blob byte-a-byte (incluyendo 0x00 interno) ====================

// Caso 12: add preserva el blob con 0x00 interno sin truncar.
void test_blob_preserved_with_embedded_null(void) {
    InflightTable t;
    const uint8_t orig[] = {0xDE, 0x00, 0xAD, 0x00, 0xBE, 0xEF};
    int idx = t.add(0x0006, 0x0007, orig, sizeof(orig), 100);
    TEST_ASSERT_TRUE(idx >= 0);
    TEST_ASSERT_EQUAL_UINT(sizeof(orig), t.blobLen(idx));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(orig, t.blob(idx), sizeof(orig));
}

// ==================== guard: blobLen > capacidad del slot ====================

// Caso 13b: add con blobLen > sizeof(slot.blob) retorna -1 sin corromper la tabla.
void test_add_rejects_oversized_blob(void) {
    InflightTable t;
    // El slot acepta hasta 305 bytes (5B header MQTT + 300B cifrado).
    // Pasar 306 bytes debe devolver -1.
    static const uint8_t bigBlob[306] = {};
    int idx = t.add(0xBEEF, 0x1234, bigBlob, sizeof(bigBlob), 1000);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, idx,
        "add debe retornar -1 si blobLen excede la capacidad del slot");
}

// ==================== release ====================

// Caso 13: release(idx) pone el slot en EMPTY.
void test_release_clears_slot(void) {
    InflightTable t;
    const uint8_t blob[] = {0x01};
    int idx = t.add(0x0010, 0x0011, blob, sizeof(blob), 100);
    TEST_ASSERT_TRUE(idx >= 0);
    t.release(idx);
    TEST_ASSERT_EQUAL(InflightTable::EMPTY, t.stage(idx));
    TEST_ASSERT_EQUAL_INT(-1, t.find(0x0010));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_add_fills_all_slots);
    RUN_TEST(test_add_returns_minus1_when_full);
    RUN_TEST(test_find_returns_correct_idx);
    RUN_TEST(test_find_returns_minus1_for_unknown);
    RUN_TEST(test_clear_and_reuse);
    RUN_TEST(test_find_after_clear_returns_minus1);
    RUN_TEST(test_due_lora_before_timeout);
    RUN_TEST(test_due_lora_at_timeout);
    RUN_TEST(test_due_mqtt_before_timeout);
    RUN_TEST(test_due_mqtt_at_timeout);
    RUN_TEST(test_due_wrap_safe_below_timeout);
    RUN_TEST(test_blob_preserved_with_embedded_null);
    RUN_TEST(test_add_rejects_oversized_blob);
    RUN_TEST(test_release_clears_slot);
    return UNITY_END();
}
