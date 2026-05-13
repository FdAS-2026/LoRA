#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

class ProtocolState {
private:
  unsigned long lastMsgSentTime;
  unsigned long lastAckReceivedTime;
  unsigned long lastHeartbeatTime;
  bool waitingForAck;
  unsigned long heartbeatInterval;

public:
  ProtocolState(unsigned long interval = 5000);
  
  void reset();
  
  bool isWaitingForAck();
  bool shouldSendHeartbeat(unsigned long currentMillis);
  
  void markMessageSent(unsigned long currentMillis);
  unsigned long markAckReceived(unsigned long currentMillis);
  
  unsigned long getLastMsgSentTime();
  unsigned long getLastAckReceivedTime();
};

#endif
