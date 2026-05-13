#include "ProtocolState.h"

ProtocolState::ProtocolState(unsigned long interval) {
  heartbeatInterval = interval;
  reset();
}

void ProtocolState::reset() {
  lastMsgSentTime = 0;
  lastAckReceivedTime = 0;
  lastHeartbeatTime = 0;
  waitingForAck = false;
}

bool ProtocolState::isWaitingForAck() {
  return waitingForAck;
}

bool ProtocolState::shouldSendHeartbeat(unsigned long currentMillis) {
  if (waitingForAck) {
    return false; // No enviamos hearbeats si estamos esperando un ACK
  }
  
  if (currentMillis - lastHeartbeatTime >= heartbeatInterval) {
    lastHeartbeatTime = currentMillis;
    return true;
  }
  return false;
}

void ProtocolState::markMessageSent(unsigned long currentMillis) {
  lastMsgSentTime = currentMillis;
  waitingForAck = true;
}

unsigned long ProtocolState::markAckReceived(unsigned long currentMillis) {
  lastAckReceivedTime = currentMillis;
  waitingForAck = false;
  
  // Devuelve la latencia
  if (currentMillis >= lastMsgSentTime) {
    return currentMillis - lastMsgSentTime;
  }
  return 0; // en caso de overflow de millis
}

unsigned long ProtocolState::getLastMsgSentTime() {
  return lastMsgSentTime;
}

unsigned long ProtocolState::getLastAckReceivedTime() {
  return lastAckReceivedTime;
}
