#ifndef RATCHET_H
#define RATCHET_H

#include <string>
#include <cstdint>
#include <functional>

// Ratchet — cadena simetrica HKDF para forward secrecy + anti-replay (CRY-01/02).
//
// A partir de la raiz CK0 (= clave ECDH+HKDF actual, ya interop-verificada) se
// derivan dos cadenas de direccion (para no reusar claves entre sentidos). Cada
// mensaje N usa una clave de mensaje MK_N; tras usar CK_i se deriva CK_{i+1} y
// se DESCARTA CK_i (forward secrecy: comprometer CK_j no revela MK_i con i<j).
//
//   CK_dir = HMAC(CK0, "dir0"|"dir1")
//   MK_i   = HMAC(CK_i, "mk")
//   CK_i+1 = HMAC(CK_i, "ck")
//
// Logica PURA con HMAC-SHA256 inyectable (mbedtls en placa, fake en tests, y un
// espejo en Dart). Los mismos bytes deben salir en firmware y app: hay un vector
// de interop compartido entre test_ratchet (C++) y ratchet_test (Dart).
class Ratchet {
public:
  // hmac(key, msg) -> 32 bytes crudos.
  using HmacFn = std::function<std::string(const std::string &key,
                                           const std::string &msg)>;

  // Direccion de ENVIO segun orden canonico de las pubkeys: 0 si la propia es
  // lexicograficamente menor, 1 si es mayor. El receptor usa la contraria.
  static int sendDir(const std::string &myPub, const std::string &theirPub);

  // Clave de cadena inicial para una direccion (0 o 1) desde la raiz CK0.
  static std::string chainRoot(const std::string &ck0, int dir, const HmacFn &h);

  // Clave de mensaje y siguiente clave de cadena desde un CK.
  static std::string messageKey(const std::string &ck, const HmacFn &h);
  static std::string nextChainKey(const std::string &ck, const HmacFn &h);

  // Deriva la MK del mensaje de indice objetivo `target` partiendo de la cadena
  // (ckIn) que esta en el indice `have` (have <= target). Avanza la cadena
  // descartando las MKs intermedias. Deja en `ckOut` la cadena en el indice
  // target+1 (para persistir) y devuelve la MK del mensaje `target`.
  // Devuelve "" si have > target (retroceso invalido).
  static std::string deriveMessageKey(const std::string &ckIn, uint32_t have,
                                      uint32_t target, const HmacFn &h,
                                      std::string &ckOut);
};

#endif
