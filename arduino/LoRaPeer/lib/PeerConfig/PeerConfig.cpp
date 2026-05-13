#include "PeerConfig.h"

PeerConfig::PeerConfig() {
  nodeId = 0;
  peerId = 0;
}

bool PeerConfig::parseSerialCommand(String s) {
  s.trim();
  bool parsedSomething = false;
  
  if (s.length() && s.indexOf("node=") >= 0) {
    int nIndex = s.indexOf("node=");
    if (nIndex >= 0) {
      String nval = s.substring(nIndex + 5);
      if (nval.indexOf(' ') > 0) nval = nval.substring(0, nval.indexOf(' '));
      nodeId = (uint8_t) nval.toInt();
      parsedSomething = true;
    }
  }
  
  if (s.length() && s.indexOf("peer=") >= 0) {
    int pIndex = s.indexOf("peer=");
    if (pIndex >= 0) {
      String pval = s.substring(pIndex + 5);
      if (pval.indexOf(' ') > 0) pval = pval.substring(0, pval.indexOf(' '));
      peerId = (uint8_t) pval.toInt();
      parsedSomething = true;
    }
  }
  
  return parsedSomething;
}

void PeerConfig::setFromDiscovery(uint8_t detectedPeerId) {
  peerId = detectedPeerId;
  nodeId = (peerId == 1) ? 2 : 1;
}

void PeerConfig::applyFallback(uint8_t storedNode, uint8_t storedPeer) {
  if (nodeId == 0 || peerId == 0) {
    if (storedNode != 0 && storedPeer != 0) {
      nodeId = storedNode;
      peerId = storedPeer;
    } else {
      nodeId = 1;
      peerId = 2;
    }
  }
}

uint8_t PeerConfig::getNodeId() {
  return nodeId;
}

uint8_t PeerConfig::getPeerId() {
  return peerId;
}
