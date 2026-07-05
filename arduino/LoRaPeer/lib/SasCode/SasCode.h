#ifndef SAS_CODE_H
#define SAS_CODE_H

#include <string>
#include <cstdint>
#include <functional>

// SasCode — Short Authentication String para cerrar el MITM del pairing (SEC-02).
//
// Tras el ECDH, ambas placas comparten el mismo secreto y conocen ambas pubkeys.
// Cada una deriva un codigo de 6 digitos = funcion determinista de
// (sharedSecret, pubkey_min, pubkey_max) con las pubkeys en ORDEN CANONICO
// (menor||mayor) para que A y B obtengan el MISMO codigo sin importar el rol.
// Los usuarios lo comparan de viva voz: si hay un MITM, los secretos compartidos
// difieren -> los codigos difieren -> se detecta.
//
// Logica PURA: la funcion hash (SHA-256 en la placa via mbedtls) se inyecta.
// En los tests se usa un hash fake determinista.
class SasCode {
public:
  // hash(msg) -> digest crudo (>=4 bytes). En placa: SHA-256.
  using HashFn = std::function<std::string(const std::string &msg)>;

  // Codigo SAS de 6 digitos (con ceros a la izquierda) como string.
  // pubA/pubB son las claves publicas crudas (32 bytes c/u). El orden en que se
  // pasen NO importa: internamente se ordenan.
  static std::string sas6(const std::string &sharedSecret,
                          const std::string &pubA, const std::string &pubB,
                          const HashFn &hash);

  // Fingerprint autocertificante de una pubkey: 8 hex (primeros 4 bytes del
  // hash de la pubkey). Sirve para mostrar/verificar que una pubkey no fue
  // sustituida. NO reemplaza la direccion LoRa del contacto.
  static std::string fingerprint(const std::string &pub, const HashFn &hash);
};

#endif
