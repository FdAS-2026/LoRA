// test_dedup.cpp — suite Unity para DedupRing (env:native)
// Corre con: pio test -e native --filter test_dedup

#include <unity.h>
#include "DedupRing.h"

void setUp(void) {}
void tearDown(void) {}

// ==================== estado inicial ====================

// Caso 1: ring vacio — cualquier seen devuelve false (sin falso positivo).
void test_empty_ring_always_false(void) {
    DedupRing r;
    TEST_ASSERT_FALSE(r.seen(0x1001, 0x0005));
    TEST_ASSERT_FALSE(r.seen(0x0000, 0x0000));
    TEST_ASSERT_FALSE(r.seen(0xFFFF, 0xFFFF));
}

// ==================== hit y miss ====================

// Caso 2: primera vez → false; repeticion del mismo par → true.
void test_first_false_then_true(void) {
    DedupRing r;
    TEST_ASSERT_FALSE(r.seen(0x1001, 0x0005));  // nuevo → registra, retorna false
    TEST_ASSERT_TRUE(r.seen(0x1001, 0x0005));   // repetido → retorna true sin re-registrar
}

// Caso 3: distinto src, mismo msgId — no colisionan.
void test_different_src_no_collision(void) {
    DedupRing r;
    TEST_ASSERT_FALSE(r.seen(0x1001, 0x0005));
    TEST_ASSERT_FALSE(r.seen(0x2002, 0x0005));  // mismo msgId pero distinto src → false
}

// Caso 4: mismo src, distinto msgId — no colisionan.
void test_different_msgid_no_collision(void) {
    DedupRing r;
    TEST_ASSERT_FALSE(r.seen(0x1001, 0x0005));
    TEST_ASSERT_FALSE(r.seen(0x1001, 0x0006));  // mismo src pero distinto msgId → false
}

// ==================== no re-registra en hit ====================

// Caso 5: seen(par visto) retorna true pero NO avanza head
// (un seen posterior del par sigue siendo true).
void test_hit_does_not_reregister(void) {
    DedupRing r;
    r.seen(0xAAAA, 0x0001);   // registra
    TEST_ASSERT_TRUE(r.seen(0xAAAA, 0x0001));   // hit
    TEST_ASSERT_TRUE(r.seen(0xAAAA, 0x0001));   // sigue siendo hit
}

// ==================== wrap del ring ====================

// Caso 6: tras registrar CAP=8 pares nuevos, el 9no desaloja el mas viejo.
// El par desalojado vuelve a dar false; el mas reciente sigue dando true.
void test_ring_wrap_evicts_oldest(void) {
    DedupRing r;
    // Registrar 8 pares distintos (llena el ring).
    for (uint16_t i = 0; i < (uint16_t)DedupRing::CAP; i++) {
        bool res = r.seen(0x0100, i);
        TEST_ASSERT_FALSE_MESSAGE(res, "par nuevo debe retornar false");
    }
    // Verificar que el primero todavia esta.
    TEST_ASSERT_TRUE(r.seen(0x0100, 0));  // hit — todavia en ring

    // Registrar un noveno par (desaloja al msgId=0 → el mas viejo).
    TEST_ASSERT_FALSE(r.seen(0x0100, 0x00FF));  // nuevo → retorna false

    // El par desalojado (src=0x0100, msgId=0) ya no esta en el ring.
    TEST_ASSERT_FALSE_MESSAGE(r.seen(0x0100, 0), "par desalojado debe retornar false");

    // El par recien registrado sigue siendo visible.
    TEST_ASSERT_TRUE(r.seen(0x0100, 0x00FF));
}

// Caso 7: segundo wrap completo — el ring sigue funcionando correctamente.
// Tras registrar 2*CAP pares, solo los ultimos CAP permanecen.
// Verificamos dos pares representativos sin mutar el ring durante la comprobacion:
//   - el ultimo registrado debe dar true
//   - un par de la primera mitad (desalojado) debe dar false
void test_ring_double_wrap(void) {
    DedupRing r;
    const uint16_t TOTAL = (uint16_t)(DedupRing::CAP * 2);
    for (uint16_t i = 0; i < TOTAL; i++) {
        r.seen(0x0200, i);  // primeros CAP seran desalojados por los segundos CAP
    }
    // El ultimo par registrado sigue en el ring.
    TEST_ASSERT_TRUE(r.seen(0x0200, (uint16_t)(TOTAL - 1)));
    // El primero (msgId=0) fue desalojado en la segunda vuelta.
    TEST_ASSERT_FALSE(r.seen(0x0200, 0));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_empty_ring_always_false);
    RUN_TEST(test_first_false_then_true);
    RUN_TEST(test_different_src_no_collision);
    RUN_TEST(test_different_msgid_no_collision);
    RUN_TEST(test_hit_does_not_reregister);
    RUN_TEST(test_ring_wrap_evicts_oldest);
    RUN_TEST(test_ring_double_wrap);
    return UNITY_END();
}
