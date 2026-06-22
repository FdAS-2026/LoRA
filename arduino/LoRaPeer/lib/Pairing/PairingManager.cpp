#include "PairingManager.h"

namespace {
const uint8_t PKT_PAIR_REQ = 2;
const uint8_t PKT_PAIR_ACK = 3;
}  // namespace

PairingManager::PairingManager() : _pairingMode(false), _pendingId(0) {}

uint16_t PairingManager::derivePairId(const std::string &pin) {
  uint32_t hash = 2166136261u;
  for (unsigned char c : pin) {
    hash ^= c;
    hash *= 16777619u;
  }
  uint16_t id = (uint16_t)((hash >> 16) ^ (hash & 0xFFFF));
  if (id == 0) id = 1;  // 0 se reserva como "sin pairId"
  return id;
}

void PairingManager::startPairing(const std::string &pin) {
  _pairingMode = true;
  _pendingId = derivePairId(pin);
}

void PairingManager::cancelPairing() {
  _pairingMode = false;
}

PairAction PairingManager::onPairPacket(uint8_t type, uint16_t pairId,
                                        uint16_t fromBoardId, uint16_t myBoardId,
                                        bool alreadyContact) {
  if (fromBoardId == myBoardId) return PAIR_NONE;  // ignora ecos propios

  // Sesion activa con el PIN correcto: completa el emparejamiento.
  if (_pairingMode && pairId == _pendingId) {
    _pairingMode = false;
    if (type == PKT_PAIR_REQ) return PAIR_SEND_ACK;   // guardar contacto + responder
    if (type == PKT_PAIR_ACK) return PAIR_COMPLETED;  // guardar contacto
    return PAIR_NONE;
  }

  // Fuera de sesion: si el peer ya es contacto y reenvia REQ (su ACK se perdio),
  // re-confirmamos de forma idempotente para que pueda completar.
  if (alreadyContact && type == PKT_PAIR_REQ) {
    return PAIR_SEND_ACK;
  }
  return PAIR_NONE;
}
