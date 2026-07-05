#ifndef MESSAGE_ROUTER_H
#define MESSAGE_ROUTER_H

// MessageRouter — decisión pura de qué hacer con un paquete DATA entrante
// (QUAL-01). Extrae la lógica de los 4 caminos NACK + entrega + replay de
// `handleDataPacket` para poder verificarla nativa, sin hardware ni cripto.
//
// El llamador (main.cpp) calcula los hechos (¿es eco propio?, ¿conozco al
// contacto?, ¿hay clave?, resultado del ratchet) y esta función decide. El
// `ratchetRc` solo se mira si el paquete llegó hasta el descifrado.

namespace MessageRouter {

enum RouteDecision {
  DROP_SELF,           // eco del propio publish -> ignorar
  NACK_UNKNOWN,        // contacto desconocido -> NACK
  NACK_NOKEY,          // sin clave E2E / e2e no listo -> NACK
  DELIVER,             // descifrado ok -> entregar + ACK
  DROP_REPLAY,         // contador ya consumido -> descartar en silencio
  NACK_UNDECRYPTABLE,  // fallo de descifrado / formato -> NACK
};

// Códigos que puede devolver el descifrado del ratchet (deben coincidir con los
// de main.cpp: >=0 éxito, -2 replay, otro <0 error).
static const int RC_REPLAY = -2;

inline RouteDecision routeIncoming(bool isSelf, bool contactKnown,
                                   bool keyReady, int ratchetRc) {
  if (isSelf) return DROP_SELF;
  if (!contactKnown) return NACK_UNKNOWN;
  if (!keyReady) return NACK_NOKEY;
  if (ratchetRc >= 0) return DELIVER;
  if (ratchetRc == RC_REPLAY) return DROP_REPLAY;
  return NACK_UNDECRYPTABLE;
}

}  // namespace MessageRouter

#endif
