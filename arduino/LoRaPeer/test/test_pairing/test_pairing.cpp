#include <unity.h>
#include "PairingManager.h"
#include "ControlCommand.h"
#include <string>

void setUp(void) {}
void tearDown(void) {}

static const uint8_t PAIR_REQ = 2;
static const uint8_t PAIR_ACK = 3;
static const uint16_t ME = 0x0001;
static const uint16_t OTHER = 0x0002;

// ==================== derivePairId ====================

void test_derive_pairid_deterministic(void) {
  TEST_ASSERT_EQUAL_UINT16(PairingManager::derivePairId("1234"),
                           PairingManager::derivePairId("1234"));
}

void test_derive_pairid_differs_per_pin(void) {
  TEST_ASSERT_NOT_EQUAL(PairingManager::derivePairId("1234"),
                        PairingManager::derivePairId("5678"));
}

void test_derive_pairid_never_zero(void) {
  TEST_ASSERT_NOT_EQUAL(0, PairingManager::derivePairId(""));
}

// ==================== Sesion de pairing ====================

void test_initial_not_pairing(void) {
  PairingManager pm;
  TEST_ASSERT_FALSE(pm.inPairingMode());
}

void test_start_pairing_sets_mode(void) {
  PairingManager pm;
  pm.startPairing("1234");
  TEST_ASSERT_TRUE(pm.inPairingMode());
  TEST_ASSERT_EQUAL_UINT16(PairingManager::derivePairId("1234"),
                           pm.pendingPairId());
}

void test_req_completes_and_acks(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  PairAction a = pm.onPairPacket(PAIR_REQ, id, OTHER, ME, false);
  TEST_ASSERT_EQUAL_INT(PAIR_SEND_ACK, a);
  TEST_ASSERT_FALSE(pm.inPairingMode());  // sale de la sesion
}

void test_ack_completes(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  PairAction a = pm.onPairPacket(PAIR_ACK, id, OTHER, ME, false);
  TEST_ASSERT_EQUAL_INT(PAIR_COMPLETED, a);
  TEST_ASSERT_FALSE(pm.inPairingMode());
}

void test_wrong_pin_ignored(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t other = PairingManager::derivePairId("9999");
  PairAction a = pm.onPairPacket(PAIR_REQ, other, OTHER, ME, false);
  TEST_ASSERT_EQUAL_INT(PAIR_NONE, a);
  TEST_ASSERT_TRUE(pm.inPairingMode());  // sigue esperando
}

void test_ignore_self_echo(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  // Paquete con el propio boardId: se ignora.
  TEST_ASSERT_EQUAL_INT(PAIR_NONE, pm.onPairPacket(PAIR_REQ, id, ME, ME, false));
}

void test_not_pairing_ignores(void) {
  PairingManager pm;
  uint16_t id = PairingManager::derivePairId("1234");
  TEST_ASSERT_EQUAL_INT(PAIR_NONE,
                        pm.onPairPacket(PAIR_REQ, id, OTHER, ME, false));
}

void test_reack_known_contact_when_idle(void) {
  // Fuera de sesion, un REQ de un contacto ya conocido => re-ACK (ACK perdido).
  PairingManager pm;
  uint16_t id = PairingManager::derivePairId("1234");
  PairAction a = pm.onPairPacket(PAIR_REQ, id, OTHER, ME, true);
  TEST_ASSERT_EQUAL_INT(PAIR_SEND_ACK, a);
  // Un ACK de un contacto conocido fuera de sesion no hace nada.
  TEST_ASSERT_EQUAL_INT(PAIR_NONE,
                        pm.onPairPacket(PAIR_ACK, id, OTHER, ME, true));
}

void test_cancel_pairing(void) {
  PairingManager pm;
  pm.startPairing("1234");
  pm.cancelPairing();
  TEST_ASSERT_FALSE(pm.inPairingMode());
}

// ==================== Parser de comandos BLE ====================

void test_parse_pair_command(void) {
  Command c = parseControlCommand("PAIR:1234");
  TEST_ASSERT_EQUAL_INT(CMD_PAIR, c.type);
  TEST_ASSERT_EQUAL_STRING("1234", c.arg.c_str());
}

void test_parse_unpair_command(void) {
  TEST_ASSERT_EQUAL_INT(CMD_UNPAIR, parseControlCommand("UNPAIR").type);
}

void test_parse_unlink_command(void) {
  TEST_ASSERT_EQUAL_INT(CMD_UNLINK, parseControlCommand("UNLINK").type);
}

void test_parse_status_command(void) {
  TEST_ASSERT_EQUAL_INT(CMD_STATUS, parseControlCommand("STATUS").type);
}

void test_parse_trims_and_is_case_insensitive(void) {
  Command c = parseControlCommand("  pair:5678  ");
  TEST_ASSERT_EQUAL_INT(CMD_PAIR, c.type);
  TEST_ASSERT_EQUAL_STRING("5678", c.arg.c_str());
}

void test_parse_unknown_is_none(void) {
  TEST_ASSERT_EQUAL_INT(CMD_NONE, parseControlCommand("hola mundo").type);
}

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_derive_pairid_deterministic);
  RUN_TEST(test_derive_pairid_differs_per_pin);
  RUN_TEST(test_derive_pairid_never_zero);
  RUN_TEST(test_initial_not_pairing);
  RUN_TEST(test_start_pairing_sets_mode);
  RUN_TEST(test_req_completes_and_acks);
  RUN_TEST(test_ack_completes);
  RUN_TEST(test_wrong_pin_ignored);
  RUN_TEST(test_ignore_self_echo);
  RUN_TEST(test_not_pairing_ignores);
  RUN_TEST(test_reack_known_contact_when_idle);
  RUN_TEST(test_cancel_pairing);
  RUN_TEST(test_parse_pair_command);
  RUN_TEST(test_parse_unpair_command);
  RUN_TEST(test_parse_unlink_command);
  RUN_TEST(test_parse_status_command);
  RUN_TEST(test_parse_trims_and_is_case_insensitive);
  RUN_TEST(test_parse_unknown_is_none);
  return UNITY_END();
}
