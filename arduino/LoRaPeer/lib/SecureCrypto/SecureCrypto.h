#ifndef SECURE_CRYPTO_H
#define SECURE_CRYPTO_H

#include <Arduino.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

// Cifrado de produccion para los mensajes que la placa publica en el broker.
// Usa RSA-2048 con padding OAEP (SHA-256) provisto por mbedtls (incluido en el
// framework Arduino-ESP32). El mensaje se cifra con la CLAVE PUBLICA y se
// codifica en base64; solo quien posee la CLAVE PRIVADA puede descifrarlo.
//
// La placa nunca conoce la clave privada. Limite de OAEP-SHA256 con RSA-2048:
// 190 bytes de texto en claro por operacion (suficiente para estos mensajes).
class SecureCrypto {
public:
  SecureCrypto();
  ~SecureCrypto();

  // Inicializa el RNG y carga la clave publica en formato PEM.
  // Devuelve false si la clave no se pudo parsear.
  bool begin(const char *publicKeyPem);

  bool isReady() const { return _ready; }

  // Cifra (RSA-OAEP-SHA256) y devuelve base64. Cadena vacia si falla o si el
  // texto supera el limite del esquema.
  String encryptBase64(const uint8_t *data, size_t len);
  String encryptBase64(const String &text);

  // Mayor cantidad de bytes de texto en claro admitidos por operacion.
  size_t maxPlaintextLen() const { return _maxPlain; }

private:
  mbedtls_pk_context _pk;
  mbedtls_entropy_context _entropy;
  mbedtls_ctr_drbg_context _ctrDrbg;
  bool _ready;
  size_t _maxPlain;
};

#endif
