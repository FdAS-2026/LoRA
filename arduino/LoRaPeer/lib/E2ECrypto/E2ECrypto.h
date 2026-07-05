#ifndef E2E_CRYPTO_H
#define E2E_CRYPTO_H

#include <Arduino.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

// Cifrado extremo a extremo entre placas (X25519 + HKDF-SHA256 + AES-256-GCM),
// compatible byte a byte con el modulo Dart de la app (paquete cryptography).
//
// Cada placa tiene su par X25519. Al emparejar se intercambian las publicas.
// Para enviar a un contacto: ECDH(miPriv, suPub) -> HKDF -> clave AES-256, y
// AES-256-GCM. Paquete de salida: nonce(12) || ciphertext || tag(16).
class E2ECrypto {
public:
  E2ECrypto();
  ~E2ECrypto();

  bool begin();  // inicializa el RNG

  // Genera un par X25519 (privada y publica de 32 bytes, little-endian RFC 7748).
  bool generateKeyPair(uint8_t priv[32], uint8_t pub[32]);
  // Deriva la publica a partir de una privada existente.
  bool publicFromPrivate(const uint8_t priv[32], uint8_t pub[32]);

  // ECDH + HKDF-SHA256 -> clave AES-256 (32 bytes) compartida con el contacto.
  bool deriveAesKey(const uint8_t myPriv[32], const uint8_t theirPub[32],
                    uint8_t aesKey[32]);

  // Cifra. out = nonce(12)||ct||tag(16). Devuelve longitud o -1. outCap >= len+28.
  // aad opcional: datos adicionales autenticados por GCM (no cifrados), p. ej. el
  // contador del ratchet que viaja en claro en el header del blob.
  int encrypt(const uint8_t aesKey[32], const uint8_t *pt, size_t len,
              uint8_t *out, size_t outCap,
              const uint8_t *aad = nullptr, size_t aadLen = 0);
  // Descifra un paquete nonce||ct||tag. Devuelve longitud del texto o -1.
  // El aad debe coincidir con el usado al cifrar o la verificacion GCM falla.
  int decrypt(const uint8_t aesKey[32], const uint8_t *in, size_t len,
              uint8_t *out, size_t outCap,
              const uint8_t *aad = nullptr, size_t aadLen = 0);

private:
  mbedtls_entropy_context _entropy;
  mbedtls_ctr_drbg_context _ctrDrbg;
  bool _ready;
};

#endif
