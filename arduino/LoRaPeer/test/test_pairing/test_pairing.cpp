#include <unity.h>
#include "PairingManager.h"
#include "ControlCommand.h"
#include <string>

void setUp(void) {}
void tearDown(void) {}

// Tipos de paquete de pairing (coinciden con el firmware).
static const uint8_t PAIR_REQ = 2;
static const uint8_t PAIR_ACK = 3;

// ==================== derivePairId ====================

void test_derive_pairid_deterministic(void) {
  // Mismo PIN => mismo pairId en ambas placas.
  TEST_ASSERT_EQUAL_UINT16(PairingManager::derivePairId("1234"),
                           PairingManager::derivePairId("1234"));
}

void test_derive_pairid_differs_per_pin(void) {
  TEST_ASSERT_NOT_EQUAL(PairingManager::derivePairId("1234"),
                        PairingManager::derivePairId("5678"));
}

void test_derive_pairid_never_zero(void) {
  // pairId 0 se reserva como "sin emparejar".
  TEST_ASSERT_NOT_EQUAL(0, PairingManager::derivePairId(""));
  TEST_ASSERT_NOT_EQUAL(0, PairingManager::derivePairId("0000"));
}

// ==================== Estado inicial ====================

void test_initial_not_paired(void) {
  PairingManager pm;
  TEST_ASSERT_FALSE(pm.isPaired());
  TEST_ASSERT_FALSE(pm.inPairingMode());
  TEST_ASSERT_EQUAL_UINT16(0, pm.pairId());
}

// ==================== Handshake ====================

void test_start_pairing_sets_mode(void) {
  PairingManager pm;
  pm.startPairing("1234");
  TEST_ASSERT_TRUE(pm.inPairingMode());
  TEST_ASSERT_EQUAL_UINT16(PairingManager::derivePairId("1234"),
                           pm.pendingPairId());
}

void test_receive_req_completes_and_acks(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  // Llega un PAIR_REQ del nodo 2 con el mismo pairId.
  PairAction action = pm.onPairPacket(PAIR_REQ, id, 2);
  TEST_ASSERT_EQUAL_INT(PAIR_SEND_ACK, action);
  TEST_ASSERT_TRUE(pm.isPaired());
  TEST_ASSERT_FALSE(pm.inPairingMode());
  TEST_ASSERT_EQUAL_UINT8(2, pm.peerId());
  TEST_ASSERT_EQUAL_UINT16(id, pm.pairId());
}

void test_receive_ack_completes(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  PairAction action = pm.onPairPacket(PAIR_ACK, id, 2);
  TEST_ASSERT_EQUAL_INT(PAIR_COMPLETED, action);
  TEST_ASSERT_TRUE(pm.isPaired());
  TEST_ASSERT_EQUAL_UINT8(2, pm.peerId());
}

void test_wrong_pin_does_not_pair(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t otherId = PairingManager::derivePairId("9999");
  PairAction action = pm.onPairPacket(PAIR_REQ, otherId, 2);
  TEST_ASSERT_EQUAL_INT(PAIR_NONE, action);
  TEST_ASSERT_FALSE(pm.isPaired());
}

void test_ignore_pair_packet_when_not_pairing(void) {
  PairingManager pm;
  uint16_t id = PairingManager::derivePairId("1234");
  PairAction action = pm.onPairPacket(PAIR_REQ, id, 2);
  TEST_ASSERT_EQUAL_INT(PAIR_NONE, action);
}

// ==================== Filtrado de datos ====================

void test_accept_data_when_unpaired(void) {
  PairingManager pm;
  // Sin emparejar, acepta (compatibilidad / pre-pairing).
  TEST_ASSERT_TRUE(pm.acceptData(0, 2));
}

void test_paired_rejects_other_network(void) {
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  pm.onPairPacket(PAIR_ACK, id, 2);
  // Acepta del peer con el pairId correcto.
  TEST_ASSERT_TRUE(pm.acceptData(id, 2));
  // Rechaza otro pairId.
  TEST_ASSERT_FALSE(pm.acceptData(id + 1, 2));
  // Rechaza otro nodo.
  TEST_ASSERT_FALSE(pm.acceptData(id, 3));
}

void test_paired_reacks_peer_req(void) {
  // Si ya esta emparejado y el peer reenvia PAIR_REQ (ACK perdido), re-confirma.
  PairingManager pm;
  pm.startPairing("1234");
  uint16_t id = PairingManager::derivePairId("1234");
  pm.onPairPacket(PAIR_ACK, id, 2);  // emparejado con N2
  TEST_ASSERT_TRUE(pm.isPaired());
  // Llega otro PAIR_REQ del mismo peer: debe responder ACK de nuevo.
  PairAction action = pm.onPairPacket(PAIR_REQ, id, 2);
  TEST_ASSERT_EQUAL_INT(PAIR_SEND_ACK, action);
  TEST_ASSERT_TRUE(pm.isPaired());
  // Un REQ de otro nodo/red ya emparejado se ignora.
  TEST_ASSERT_EQUAL_INT(PAIR_NONE, pm.onPairPacket(PAIR_REQ, id, 3));
  TEST_ASSERT_EQUAL_INT(PAIR_NONE, pm.onPairPacket(PAIR_REQ, id + 9, 2));
}

void test_unpair_clears_state(void) {
  PairingManager pm;
  pm.startPairing("1234");
  pm.onPairPacket(PAIR_ACK, PairingManager::derivePairId("1234"), 2);
  pm.unpair();
  TEST_ASSERT_FALSE(pm.isPaired());
  TEST_ASSERT_EQUAL_UINT16(0, pm.pairId());
  TEST_ASSERT_TRUE(pm.acceptData(0, 5));  // vuelve a aceptar todo
}

void test_load_state_restores_pairing(void) {
  PairingManager pm;
  pm.loadState(true, 4321, 2);
  TEST_ASSERT_TRUE(pm.isPaired());
  TEST_ASSERT_EQUAL_UINT16(4321, pm.pairId());
  TEST_ASSERT_EQUAL_UINT8(2, pm.peerId());
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
  RUN_TEST(test_initial_not_paired);
  RUN_TEST(test_start_pairing_sets_mode);
  RUN_TEST(test_receive_req_completes_and_acks);
  RUN_TEST(test_receive_ack_completes);
  RUN_TEST(test_wrong_pin_does_not_pair);
  RUN_TEST(test_ignore_pair_packet_when_not_pairing);
  RUN_TEST(test_accept_data_when_unpaired);
  RUN_TEST(test_paired_rejects_other_network);
  RUN_TEST(test_paired_reacks_peer_req);
  RUN_TEST(test_unpair_clears_state);
  RUN_TEST(test_load_state_restores_pairing);
  RUN_TEST(test_parse_pair_command);
  RUN_TEST(test_parse_unpair_command);
  RUN_TEST(test_parse_unlink_command);
  RUN_TEST(test_parse_status_command);
  RUN_TEST(test_parse_trims_and_is_case_insensitive);
  RUN_TEST(test_parse_unknown_is_none);
  return UNITY_END();
}
