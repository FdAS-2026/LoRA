#include "E2ECrypto.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <string.h>

namespace {
const char *HKDF_INFO = "lora-e2e-v1";  // debe coincidir con la app

// HKDF-SHA256 con salt vacio y L=32 (un solo bloque). mbedtls_hkdf no esta
// habilitado en el mbedtls del ESP32, asi que se arma con HMAC-SHA256.
// Clamping del escalar X25519 (RFC 7748). mbedtls valida la clave y rechaza
// escalares sin clampear; los impl. estandar (incl. la app) clampan internamente.
void clampScalar(const uint8_t in[32], uint8_t out[32]) {
  memcpy(out, in, 32);
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
}

bool hkdfSha256(const uint8_t *ikm, size_t ikmLen, const char *info,
                uint8_t out[32]) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;
  uint8_t salt[32] = {0};  // salt vacio => 32 ceros
  uint8_t prk[32];
  // Extract: PRK = HMAC(salt, IKM)
  if (mbedtls_md_hmac(md, salt, sizeof(salt), ikm, ikmLen, prk) != 0) {
    return false;
  }
  // Expand (L=32): T1 = HMAC(PRK, info || 0x01)
  uint8_t t1in[64];
  size_t infoLen = strlen(info);
  memcpy(t1in, info, infoLen);
  t1in[infoLen] = 0x01;
  bool ok = mbedtls_md_hmac(md, prk, sizeof(prk), t1in, infoLen + 1, out) == 0;
  memset(prk, 0, sizeof(prk));
  return ok;
}
}  // namespace

E2ECrypto::E2ECrypto() : _ready(false) {
  mbedtls_entropy_init(&_entropy);
  mbedtls_ctr_drbg_init(&_ctrDrbg);
}

E2ECrypto::~E2ECrypto() {
  mbedtls_ctr_drbg_free(&_ctrDrbg);
  mbedtls_entropy_free(&_entropy);
}

bool E2ECrypto::begin() {
  const char *pers = "lora_e2e_x25519";
  int rc = mbedtls_ctr_drbg_seed(&_ctrDrbg, mbedtls_entropy_func, &_entropy,
                                 (const unsigned char *)pers, strlen(pers));
  _ready = (rc == 0);
  return _ready;
}

bool E2ECrypto::generateKeyPair(uint8_t priv[32], uint8_t pub[32]) {
  if (!_ready) return false;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);

  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
      mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random,
                              &_ctrDrbg) == 0 &&
      mbedtls_mpi_write_binary_le(&d, priv, 32) == 0 &&
      mbedtls_mpi_write_binary_le(&Q.X, pub, 32) == 0) {
    ok = true;
  }

  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

bool E2ECrypto::publicFromPrivate(const uint8_t priv[32], uint8_t pub[32]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);

  bool ok = false;
  uint8_t clamped[32];
  clampScalar(priv, clamped);
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
      mbedtls_mpi_read_binary_le(&d, clamped, 32) == 0 &&
      mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random,
                      &_ctrDrbg) == 0 &&
      mbedtls_mpi_write_binary_le(&Q.X, pub, 32) == 0) {
    ok = true;
  }

  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

bool E2ECrypto::deriveAesKey(const uint8_t myPriv[32], const uint8_t theirPub[32],
                            uint8_t aesKey[32]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d, z;
  mbedtls_ecp_point Qp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);
  mbedtls_ecp_point_init(&Qp);

  bool ok = false;
  uint8_t shared[32];
  uint8_t clamped[32];
  clampScalar(myPriv, clamped);
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
      mbedtls_mpi_read_binary_le(&d, clamped, 32) == 0 &&
      mbedtls_mpi_read_binary_le(&Qp.X, theirPub, 32) == 0 &&
      mbedtls_mpi_lset(&Qp.Z, 1) == 0 &&
      mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random,
                                  &_ctrDrbg) == 0 &&
      mbedtls_mpi_write_binary_le(&z, shared, 32) == 0) {
    // HKDF-SHA256(salt vacio, info) -> 32 bytes
    ok = hkdfSha256(shared, 32, HKDF_INFO, aesKey);
  }

  memset(shared, 0, sizeof(shared));
  mbedtls_ecp_point_free(&Qp);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

int E2ECrypto::encrypt(const uint8_t aesKey[32], const uint8_t *pt, size_t len,
                       uint8_t *out, size_t outCap,
                       const uint8_t *aad, size_t aadLen) {
  if (!_ready || outCap < len + 28) return -1;
  uint8_t *nonce = out;            // 12 bytes
  uint8_t *ct = out + 12;          // len bytes
  uint8_t *tag = out + 12 + len;   // 16 bytes
  if (mbedtls_ctr_drbg_random(&_ctrDrbg, nonce, 12) != 0) return -1;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = -1;
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 256) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, 12,
                                aad, aadLen, pt, ct, 16, tag) == 0) {
    rc = (int)(len + 28);
  }
  mbedtls_gcm_free(&gcm);
  return rc;
}

int E2ECrypto::decrypt(const uint8_t aesKey[32], const uint8_t *in, size_t len,
                       uint8_t *out, size_t outCap,
                       const uint8_t *aad, size_t aadLen) {
  if (len < 28) return -1;
  size_t ctLen = len - 28;
  if (outCap < ctLen) return -1;
  const uint8_t *nonce = in;
  const uint8_t *ct = in + 12;
  const uint8_t *tag = in + 12 + ctLen;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = -1;
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 256) == 0 &&
      mbedtls_gcm_auth_decrypt(&gcm, ctLen, nonce, 12, aad, aadLen, tag, 16,
                               ct, out) == 0) {
    rc = (int)ctLen;
  }
  mbedtls_gcm_free(&gcm);
  return rc;
}
