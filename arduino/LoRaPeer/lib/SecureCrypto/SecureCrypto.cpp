#include "SecureCrypto.h"
#include <mbedtls/rsa.h>
#include <mbedtls/base64.h>

SecureCrypto::SecureCrypto() : _ready(false), _maxPlain(0) {
  mbedtls_pk_init(&_pk);
  mbedtls_entropy_init(&_entropy);
  mbedtls_ctr_drbg_init(&_ctrDrbg);
}

SecureCrypto::~SecureCrypto() {
  mbedtls_pk_free(&_pk);
  mbedtls_ctr_drbg_free(&_ctrDrbg);
  mbedtls_entropy_free(&_entropy);
}

bool SecureCrypto::begin(const char *publicKeyPem) {
  const char *pers = "lorapeer_rsa_oaep";
  if (mbedtls_ctr_drbg_seed(&_ctrDrbg, mbedtls_entropy_func, &_entropy,
                            (const unsigned char *)pers, strlen(pers)) != 0) {
    return false;
  }

  size_t pemLen = strlen(publicKeyPem) + 1;  // mbedtls exige incluir el '\0'
  if (mbedtls_pk_parse_public_key(&_pk, (const unsigned char *)publicKeyPem,
                                  pemLen) != 0) {
    return false;
  }
  if (mbedtls_pk_get_type(&_pk) != MBEDTLS_PK_RSA) {
    return false;
  }

  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(_pk);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  size_t keyLen = mbedtls_rsa_get_len(rsa);  // 256 bytes para RSA-2048
  const size_t hashLen = 32;                 // SHA-256
  _maxPlain = keyLen - 2 * hashLen - 2;       // limite de OAEP
  _ready = true;
  return true;
}

String SecureCrypto::encryptBase64(const uint8_t *data, size_t len) {
  if (!_ready || len == 0 || len > _maxPlain) return String();

  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(_pk);
  size_t keyLen = mbedtls_rsa_get_len(rsa);

  unsigned char cipher[512];  // suficiente para RSA-2048 (256 bytes)
  if (keyLen > sizeof(cipher)) return String();

  int rc = mbedtls_pk_encrypt(&_pk, data, len, cipher, &keyLen, sizeof(cipher),
                              mbedtls_ctr_drbg_random, &_ctrDrbg);
  if (rc != 0) return String();

  // base64
  size_t b64Len = 0;
  mbedtls_base64_encode(nullptr, 0, &b64Len, cipher, keyLen);  // tamano requerido
  unsigned char *b64 = (unsigned char *)malloc(b64Len + 1);
  if (!b64) return String();

  String out;
  size_t written = 0;
  if (mbedtls_base64_encode(b64, b64Len, &written, cipher, keyLen) == 0) {
    b64[written] = '\0';
    out = String((const char *)b64);
  }
  free(b64);
  return out;
}

String SecureCrypto::encryptBase64(const String &text) {
  return encryptBase64((const uint8_t *)text.c_str(), text.length());
}
