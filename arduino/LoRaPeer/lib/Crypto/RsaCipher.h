#ifndef RSA_CIPHER_H
#define RSA_CIPHER_H

#include <string>
#include <vector>
#include <cstdint>

// Par de claves RSA (de demostracion, aritmetica de 32 bits).
struct RsaKeyPair {
  uint32_t e;  // exponente publico
  uint32_t d;  // exponente privado
  uint32_t n;  // modulo (= p * q)
  bool valid;  // false si los parametros no producen un par valido
};

// Cifrado RSA "de libro de texto" en C++ puro (sin dependencias de Arduino).
// Pensado para encriptar los mensajes enviados al broker: se cifran con la
// clave publica (e, n) y solo quien tiene la privada (d, n) puede descifrarlos.
//
// Cada byte del mensaje se cifra de forma independiente y se serializa como
// un bloque de 4 bytes (uint32 little-endian). Es una implementacion didactica
// para el alcance del proyecto, no apta para produccion real.
class RsaCipher {
public:
  // Genera el par a partir de dos primos y un exponente publico e.
  // valid = false si e no es coprimo con phi = (p-1)(q-1) o n <= 255.
  static RsaKeyPair generate(uint32_t p, uint32_t q, uint32_t e);

  // Cifra con la clave publica (e, n). Cadena vacia => vector vacio.
  static std::vector<uint8_t> encrypt(const std::string &plain, uint32_t e, uint32_t n);

  // Descifra con la clave privada (d, n). Datos invalidos => cadena vacia.
  static std::string decrypt(const std::vector<uint8_t> &cipher, uint32_t d, uint32_t n);
};

#endif
