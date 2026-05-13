#ifndef MESSAGE_MANAGER_H
#define MESSAGE_MANAGER_H

#include <Arduino.h>

const int MSG_BUFFER_SIZE = 10;

struct Message {
  uint8_t from;
  String text;
  unsigned long timestamp;
  int rssi;
  bool isBLE;
};

class MessageManager {
private:
  Message msgBuffer[MSG_BUFFER_SIZE];
  int msgBufferIdx;

public:
  MessageManager();
  void addMessage(uint8_t msgFrom, const String &text, unsigned long ts, int rssi, bool isBLE);
  Message getMessage(int index);
  int getHeadIndex();
  int getSize();
  void clear();
};

#endif
