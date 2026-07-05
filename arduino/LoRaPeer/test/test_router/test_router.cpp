// test_router.cpp — suite Unity para MessageRouter (env:native)
// Corre con: pio test -e native --filter test_router
// Verifica la tabla de verdad completa del ruteo de un DATA entrante (QUAL-01).

#include <unity.h>
#include "MessageRouter.h"

using namespace MessageRouter;

void setUp(void) {}
void tearDown(void) {}

void test_self_echo_dropped(void) {
  // isSelf gana sobre todo lo demas.
  TEST_ASSERT_EQUAL(DROP_SELF, routeIncoming(true, true, true, 0));
  TEST_ASSERT_EQUAL(DROP_SELF, routeIncoming(true, false, false, -1));
}

void test_unknown_contact_nacks(void) {
  TEST_ASSERT_EQUAL(NACK_UNKNOWN, routeIncoming(false, false, true, 0));
}

void test_no_key_nacks(void) {
  TEST_ASSERT_EQUAL(NACK_NOKEY, routeIncoming(false, true, false, 0));
}

void test_deliver_on_success(void) {
  TEST_ASSERT_EQUAL(DELIVER, routeIncoming(false, true, true, 0));
  TEST_ASSERT_EQUAL(DELIVER, routeIncoming(false, true, true, 42));  // len>0
}

void test_replay_dropped(void) {
  TEST_ASSERT_EQUAL(DROP_REPLAY, routeIncoming(false, true, true, RC_REPLAY));
}

void test_decrypt_failure_nacks(void) {
  TEST_ASSERT_EQUAL(NACK_UNDECRYPTABLE, routeIncoming(false, true, true, -1));
  TEST_ASSERT_EQUAL(NACK_UNDECRYPTABLE, routeIncoming(false, true, true, -3));
}

void test_precedence_unknown_before_key(void) {
  // Un contacto desconocido NO revela si habia clave: gana NACK_UNKNOWN.
  TEST_ASSERT_EQUAL(NACK_UNKNOWN, routeIncoming(false, false, false, -1));
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_self_echo_dropped);
  RUN_TEST(test_unknown_contact_nacks);
  RUN_TEST(test_no_key_nacks);
  RUN_TEST(test_deliver_on_success);
  RUN_TEST(test_replay_dropped);
  RUN_TEST(test_decrypt_failure_nacks);
  RUN_TEST(test_precedence_unknown_before_key);
  return UNITY_END();
}
