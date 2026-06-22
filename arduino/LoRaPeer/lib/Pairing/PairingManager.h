#ifndef PAIRING_MANAGER_H
#define PAIRING_MANAGER_H

#include <string>
#include <cstdint>

// Resultado de procesar un paquete de pairing entrante.
enum PairAction {
  PAIR_NONE,       // ignorar
  PAIR_SEND_ACK,   // guardar contacto y responder PAIR_ACK
  PAIR_COMPLETED   // emparejamiento completado (recibido el ACK)
};

// Gestiona la SESION de emparejamiento entre placas mediante un PIN compartido.
// El PIN deriva un pairId que autoriza la sesion: solo placas con el mismo PIN
// se reconocen. El contacto resultante (id, nombre, clave publica) lo guarda el
// llamador en la ContactBook; aqui solo se decide la accion. Logica pura.
//
// Multi-contacto: cada sesion (un PIN) agrega un contacto. Para sumar mas
// contactos se inicia otra sesion con otro PIN.
class PairingManager {
public:
  PairingManager();

  // pairId determinista (FNV-1a de 16 bits) desde el PIN. Nunca 0.
  static uint16_t derivePairId(const std::string &pin);

  void startPairing(const std::string &pin);
  void cancelPairing();

  bool inPairingMode() const { return _pairingMode; }
  uint16_t pendingPairId() const { return _pendingId; }

  // Procesa un paquete de pairing (type 2=REQ, 3=ACK).
  // - fromBoardId: id de la placa remota; myBoardId: id propio (se ignora self).
  // - alreadyContact: si la placa remota ya esta en la agenda (para re-ACK
  //   idempotente si su ACK se perdio).
  PairAction onPairPacket(uint8_t type, uint16_t pairId, uint16_t fromBoardId,
                          uint16_t myBoardId, bool alreadyContact);

private:
  bool _pairingMode;
  uint16_t _pendingId;
};

#endif
