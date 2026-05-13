#ifndef PEER_CONFIG_H
#define PEER_CONFIG_H

#include <Arduino.h>

class PeerConfig {
private:
  uint8_t nodeId;
  uint8_t peerId;

public:
  PeerConfig();
  
  // Analiza entrada de Serial "node=1 peer=2"
  bool parseSerialCommand(String cmd);
  
  // Establece IDs basados en el descubrimiento de un paquete
  void setFromDiscovery(uint8_t detectedPeerId);
  
  // Aplica los IDs por defecto o los guardados
  void applyFallback(uint8_t storedNode, uint8_t storedPeer);
  
  uint8_t getNodeId();
  uint8_t getPeerId();
};

#endif
