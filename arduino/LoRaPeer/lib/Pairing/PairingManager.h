#ifndef PAIRING_MANAGER_H
#define PAIRING_MANAGER_H

#include <string>
#include <cstdint>

// Resultado de procesar un paquete de pairing entrante.
enum PairAction {
  PAIR_NONE,       // nada que hacer
  PAIR_SEND_ACK,   // emparejado; responder un PAIR_ACK al peer
  PAIR_COMPLETED   // emparejado tras recibir el ACK
};

// Gestiona el emparejamiento LoRa entre dos placas mediante un PIN compartido.
// Logica pura (sin Arduino) para poder probarla sin hardware.
//
// Flujo: la app envia el mismo PIN a ambas placas (startPairing). Ambas derivan
// el mismo pairId y emiten PAIR_REQ. Al recibir un REQ/ACK con el pairId
// correcto, quedan emparejadas y guardan el nodo del peer. Luego solo aceptan
// datos del peer con ese pairId (acceptData), ignorando otras redes en rango.
class PairingManager {
public:
  PairingManager();

  // Deriva un pairId determinista (FNV-1a de 16 bits) desde el PIN. Nunca 0.
  static uint16_t derivePairId(const std::string &pin);

  // Restaura el estado guardado (p. ej. desde NVS).
  void loadState(bool paired, uint16_t pairId, uint8_t peerId);

  // Inicia el modo de emparejamiento con el PIN dado.
  void startPairing(const std::string &pin);
  void cancelPairing();
  void unpair();

  bool isPaired() const { return _paired; }
  bool inPairingMode() const { return _pairingMode; }
  uint16_t pairId() const { return _pairId; }
  uint8_t peerId() const { return _peerId; }
  uint16_t pendingPairId() const { return _pendingId; }

  // Procesa un paquete de pairing (type 2=REQ, 3=ACK) recibido por LoRa.
  PairAction onPairPacket(uint8_t type, uint16_t pairId, uint8_t fromNode);

  // Decide si aceptar un paquete de datos. Sin emparejar acepta todo; ya
  // emparejado exige pairId y nodo del peer correctos.
  bool acceptData(uint16_t pairId, uint8_t fromNode) const;

private:
  bool _paired;
  bool _pairingMode;
  uint16_t _pairId;
  uint16_t _pendingId;
  uint8_t _peerId;
};

#endif
