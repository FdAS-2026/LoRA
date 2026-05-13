#include <Arduino.h>
#include <unity.h>
#include "MessageManager.h"
#include "ProtocolState.h"
#include "PeerConfig.h"
#include "CloudManager.h"

MessageManager msgManager;
ProtocolState protocol(5000);
PeerConfig peerConfig;
CloudManager cloud;

void setUp(void) {
  // Configuración antes de cada prueba
  msgManager.clear();
  protocol.reset();
  peerConfig = PeerConfig();
}

void tearDown(void) {
  // Limpieza después de cada prueba
}

// ==================== Pruebas de MessageManager ====================

void test_initial_state(void) {
  TEST_ASSERT_EQUAL_INT(0, msgManager.getHeadIndex());
  Message m = msgManager.getMessage(0);
  TEST_ASSERT_EQUAL_UINT8(0, m.from);
  TEST_ASSERT_EQUAL_STRING("", m.text.c_str());
}

void test_add_single_message(void) {
  msgManager.addMessage(1, "Hola", 1000, -50, true);
  TEST_ASSERT_EQUAL_INT(1, msgManager.getHeadIndex());
  Message m = msgManager.getMessage(0);
  TEST_ASSERT_EQUAL_UINT8(1, m.from);
  TEST_ASSERT_EQUAL_STRING("Hola", m.text.c_str());
  TEST_ASSERT_EQUAL_UINT32(1000, m.timestamp);
  TEST_ASSERT_EQUAL_INT(-50, m.rssi);
  TEST_ASSERT_TRUE(m.isBLE);
}

void test_buffer_rollover(void) {
  int size = msgManager.getSize();
  for (int i = 0; i < size + 2; i++) {
    msgManager.addMessage(2, String("Msg ") + String(i), i * 100, -60, false);
  }
  TEST_ASSERT_EQUAL_INT(2, msgManager.getHeadIndex());
  Message m0 = msgManager.getMessage(0);
  String expectedText = String("Msg ") + String(size);
  TEST_ASSERT_EQUAL_STRING(expectedText.c_str(), m0.text.c_str());
}

void test_message_truncation(void) {
  msgManager.addMessage(3, "Este mensaje es demasiado largo para el buffer", 2000, -40, false);
  Message m = msgManager.getMessage(0);
  TEST_ASSERT_EQUAL_STRING("Este mensaje es dema", m.text.c_str());
}

void test_invalid_index(void) {
  msgManager.addMessage(1, "Test", 1000, -50, false);
  Message mNeg = msgManager.getMessage(-1);
  TEST_ASSERT_EQUAL_UINT8(0, mNeg.from);
  
  Message mOut = msgManager.getMessage(msgManager.getSize() + 5);
  TEST_ASSERT_EQUAL_UINT8(0, mOut.from);
}

void test_clear(void) {
  msgManager.addMessage(1, "Test", 1000, -50, false);
  msgManager.clear();
  TEST_ASSERT_EQUAL_INT(0, msgManager.getHeadIndex());
  Message m = msgManager.getMessage(0);
  TEST_ASSERT_EQUAL_UINT8(0, m.from);
}

// ==================== Pruebas de ProtocolState ====================

void test_protocol_initial_state(void) {
  TEST_ASSERT_FALSE(protocol.isWaitingForAck());
  TEST_ASSERT_EQUAL_UINT32(0, protocol.getLastMsgSentTime());
}

void test_should_send_heartbeat(void) {
  TEST_ASSERT_FALSE(protocol.shouldSendHeartbeat(1000));
  TEST_ASSERT_TRUE(protocol.shouldSendHeartbeat(5000));
  TEST_ASSERT_FALSE(protocol.shouldSendHeartbeat(6000));
  TEST_ASSERT_TRUE(protocol.shouldSendHeartbeat(10000));
}

void test_heartbeat_not_sent_while_waiting_ack(void) {
  protocol.markMessageSent(1000);
  TEST_ASSERT_TRUE(protocol.isWaitingForAck());
  TEST_ASSERT_FALSE(protocol.shouldSendHeartbeat(6000)); 
}

void test_mark_message_sent_and_ack_latency(void) {
  protocol.markMessageSent(2000);
  TEST_ASSERT_TRUE(protocol.isWaitingForAck());
  unsigned long lat = protocol.markAckReceived(2500);
  TEST_ASSERT_FALSE(protocol.isWaitingForAck());
  TEST_ASSERT_EQUAL_UINT32(500, lat);
  TEST_ASSERT_EQUAL_UINT32(2500, protocol.getLastAckReceivedTime());
}

// ==================== Pruebas de PeerConfig ====================

void test_peerconfig_default(void) {
  TEST_ASSERT_EQUAL_UINT8(0, peerConfig.getNodeId());
  TEST_ASSERT_EQUAL_UINT8(0, peerConfig.getPeerId());
}

void test_peerconfig_parse_serial(void) {
  bool parsed = peerConfig.parseSerialCommand("node=5 peer=6");
  TEST_ASSERT_TRUE(parsed);
  TEST_ASSERT_EQUAL_UINT8(5, peerConfig.getNodeId());
  TEST_ASSERT_EQUAL_UINT8(6, peerConfig.getPeerId());
}

void test_peerconfig_parse_serial_partial(void) {
  bool parsed = peerConfig.parseSerialCommand("node=3");
  TEST_ASSERT_TRUE(parsed);
  TEST_ASSERT_EQUAL_UINT8(3, peerConfig.getNodeId());
  TEST_ASSERT_EQUAL_UINT8(0, peerConfig.getPeerId());
}

void test_peerconfig_discovery(void) {
  peerConfig.setFromDiscovery(2);
  TEST_ASSERT_EQUAL_UINT8(2, peerConfig.getPeerId());
  TEST_ASSERT_EQUAL_UINT8(1, peerConfig.getNodeId());
  
  peerConfig.setFromDiscovery(1);
  TEST_ASSERT_EQUAL_UINT8(1, peerConfig.getPeerId());
  TEST_ASSERT_EQUAL_UINT8(2, peerConfig.getNodeId());
}

void test_peerconfig_fallback(void) {
  peerConfig.applyFallback(4, 5);
  TEST_ASSERT_EQUAL_UINT8(4, peerConfig.getNodeId());
  TEST_ASSERT_EQUAL_UINT8(5, peerConfig.getPeerId());
  
  peerConfig = PeerConfig();
  peerConfig.applyFallback(0, 0);
  TEST_ASSERT_EQUAL_UINT8(1, peerConfig.getNodeId());
  TEST_ASSERT_EQUAL_UINT8(2, peerConfig.getPeerId());
}

// ==================== Pruebas de CloudManager ====================

void test_cloud_topics(void) {
  TEST_ASSERT_EQUAL_STRING("lorapeer/node1/tx", cloud.getTxTopic(1).c_str());
  TEST_ASSERT_EQUAL_STRING("lorapeer/node2/rx", cloud.getRxTopic(2).c_str());
}

void setup() {
  delay(2000); // Dar tiempo al monitor serial
  
  UNITY_BEGIN();
  
  RUN_TEST(test_initial_state);
  RUN_TEST(test_add_single_message);
  RUN_TEST(test_buffer_rollover);
  RUN_TEST(test_message_truncation);
  RUN_TEST(test_invalid_index);
  RUN_TEST(test_clear);
  
  RUN_TEST(test_protocol_initial_state);
  RUN_TEST(test_should_send_heartbeat);
  RUN_TEST(test_heartbeat_not_sent_while_waiting_ack);
  RUN_TEST(test_mark_message_sent_and_ack_latency);
  
  RUN_TEST(test_peerconfig_default);
  RUN_TEST(test_peerconfig_parse_serial);
  RUN_TEST(test_peerconfig_parse_serial_partial);
  RUN_TEST(test_peerconfig_discovery);
  RUN_TEST(test_peerconfig_fallback);
  
  RUN_TEST(test_cloud_topics);
  
  UNITY_END();
}

void loop() {
  // No hacer nada en el loop
}
