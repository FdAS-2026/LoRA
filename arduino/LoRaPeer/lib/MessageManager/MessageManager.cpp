#include "MessageManager.h"

MessageManager::MessageManager() {
  msgBufferIdx = 0;
  clear();
}

void MessageManager::clear() {
  msgBufferIdx = 0;
  for (int i = 0; i < MSG_BUFFER_SIZE; i++) {
    msgBuffer[i].from = 0;
    msgBuffer[i].text = "";
    msgBuffer[i].timestamp = 0;
    msgBuffer[i].rssi = 0;
    msgBuffer[i].isBLE = false;
  }
}

void MessageManager::addMessage(uint8_t msgFrom, const String &text, unsigned long ts, int rssi, bool isBLE) {
  msgBuffer[msgBufferIdx].from = msgFrom;
  msgBuffer[msgBufferIdx].text = text.substring(0, 20);
  msgBuffer[msgBufferIdx].timestamp = ts;
  msgBuffer[msgBufferIdx].rssi = rssi;
  msgBuffer[msgBufferIdx].isBLE = isBLE;
  msgBufferIdx = (msgBufferIdx + 1) % MSG_BUFFER_SIZE;
}

Message MessageManager::getMessage(int index) {
  if (index >= 0 && index < MSG_BUFFER_SIZE) {
    return msgBuffer[index];
  }
  Message emptyMsg = {0, "", 0, 0, false};
  return emptyMsg;
}

int MessageManager::getHeadIndex() {
  return msgBufferIdx;
}

int MessageManager::getSize() {
  return MSG_BUFFER_SIZE;
}
