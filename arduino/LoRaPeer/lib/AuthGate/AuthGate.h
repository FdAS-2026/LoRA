#ifndef AUTH_GATE_H
#define AUTH_GATE_H

#include <string>
#include <cstdint>
#include <functional>

// AuthGate — autenticacion del canal de control BLE por token de sesion (SEC-01).
//
// Modelo (trust-on-first-use): la placa tiene un secreto de claim de 16 bytes
// (claimSecret) compartido con el telefono dueno. En cada conexion:
//   1. La placa genera un nonce y lo envia (NONCE:<hex>).
//   2. El telefono responde AUTH:<hex(HMAC(claimSecret, nonce))>.
//   3. La placa verifica (constant-time) y emite un token de sesion.
//   4. Cada comando siguiente viaja como "<token>|<comando>".
//
// Esta clase es LOGICA PURA y testeable en nativo: la funcion HMAC se inyecta
// (en la placa se pasa mbedtls HMAC-SHA256; en los tests un fake determinista).
// No conoce BLE ni NVS.
class AuthGate {
public:
  // hmac(key, msg) -> digest crudo (>=4 bytes). key y msg son bytes crudos.
  using HmacFn = std::function<std::string(const std::string &key,
                                           const std::string &msg)>;

  explicit AuthGate(HmacFn hmac) : _hmac(hmac), _authed(false) {}

  // Nonce hex determinista desde una semilla de 32 bits (en placa: esp_random()).
  // 8 caracteres hex (32 bits de nonce). Suficiente contra replay dentro de una
  // sesion; se renueva en cada conexion.
  static std::string makeNonce(uint32_t seed);

  // Inicia un desafio con el nonce dado. Invalida cualquier sesion previa.
  void beginChallenge(const std::string &nonceHex);

  // Verifica la respuesta del cliente (clientMacHex = hex(HMAC(secret,nonce))).
  // Si coincide (constant-time), emite y guarda el token de sesion y lo
  // devuelve. Si falla o no hay desafio activo, devuelve "" y no autentica.
  // El token es 8 hex = primeros 4 bytes de HMAC(secret, "T" + nonceBytes).
  std::string verifyResponse(const std::string &secret,
                             const std::string &clientMacHex);

  // Comando entrante con envelope "<token>|<payload>". Si hay sesion autenticada
  // y el token coincide (constant-time), devuelve true y deja el payload en
  // payloadOut. Sin sesion, token invalido o formato malo -> false.
  bool checkCommand(const std::string &input, std::string &payloadOut) const;

  // true si un comando de handshake no necesita token (lo pide/manda la app
  // antes de autenticar). Son: "NONCE" (pedido de nonce) y "AUTH:<...>".
  static bool isHandshakeCommand(const std::string &input);

  bool isAuthed() const { return _authed; }
  const std::string &token() const { return _token; }

  // Corta la sesion (p. ej. al desconectar el BLE).
  void reset();

private:
  HmacFn _hmac;
  std::string _nonce;   // nonce hex del desafio activo
  std::string _token;   // token hex de la sesion activa ("" si no autenticada)
  bool _authed;
};

#endif
