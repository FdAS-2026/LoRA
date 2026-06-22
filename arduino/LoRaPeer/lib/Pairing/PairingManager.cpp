#include "PairingManager.h"

namespace {
const uint8_t PKT_PAIR_REQ = 2;
const uint8_t PKT_PAIR_ACK = 3;
}  // namespace

PairingManager::PairingManager()
    : _paired(false),
      _pairingMode(false),
      _pairId(0),
      _pendingId(0),
      _peerId(0) {}

uint16_t PairingManager::derivePairId(const std::string &pin) {
  // FNV-1a de 32 bits, plegado a 16 bits.
  uint32_t hash = 2166136261u;
  for (unsigned char c : pin) {
    hash ^= c;
    hash *= 16777619u;
  }
  uint16_t id = (uint16_t)((hash >> 16) ^ (hash & 0xFFFF));
  if (id == 0) id = 1;  // 0 se reserva para "sin emparejar"
  return id;
}

void PairingManager::loadState(bool paired, uint16_t pairId, uint8_t peerId) {
  _paired = paired;
  _pairId = pairId;
  _peerId = peerId;
  _pairingMode = false;
}

void PairingManager::startPairing(const std::string &pin) {
  _pairingMode = true;
  _pendingId = derivePairId(pin);
}

void PairingManager::cancelPairing() {
  _pairingMode = false;
}

void PairingManager::unpair() {
  _paired = false;
  _pairingMode = false;
  _pairId = 0;
  _pendingId = 0;
  _peerId = 0;
}

PairAction PairingManager::onPairPacket(uint8_t type, uint16_t pairId,
                                        uint8_t fromNode) {
  if (!_pairingMode || pairId != _pendingId) {
    return PAIR_NONE;
  }

  _paired = true;
  _pairingMode = false;
  _pairId = pairId;
  _peerId = fromNode;

  if (type == PKT_PAIR_REQ) {
    return PAIR_SEND_ACK;  // confirmar al peer
  }
  if (type == PKT_PAIR_ACK) {
    return PAIR_COMPLETED;
  }
  return PAIR_NONE;
}

bool PairingManager::acceptData(uint16_t pairId, uint8_t fromNode) const {
  if (!_paired) return true;  // pre-pairing: acepta todo
  return pairId == _pairId && fromNode == _peerId;
}
