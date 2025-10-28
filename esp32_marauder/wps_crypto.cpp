#include "wps_crypto.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/dhm.h"

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1); // 1 for HMAC

  mbedtls_md_hmac_starts(&ctx, key, key_len);
  mbedtls_md_hmac_update(&ctx, data, data_len);
  mbedtls_md_hmac_finish(&ctx, out);

  mbedtls_md_free(&ctx);
}

void sha256(const uint8_t *data, size_t data_len, uint8_t *out) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
  mbedtls_sha256_update(&ctx, data, data_len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

void aes_128_ecb_encrypt(const uint8_t *key, const uint8_t *data, uint8_t *out) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key, 128);
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, data, out);
  mbedtls_aes_free(&ctx);
}

bool diffie_hellman(const uint8_t *p, const uint8_t *g,
                    const uint8_t *priv_key, size_t priv_key_len,
                    uint8_t *pub_key, size_t &pub_key_len,
                    uint8_t *secret_key, size_t &secret_key_len) {
  mbedtls_dhm_context dhm;
  mbedtls_dhm_init(&dhm);

  // Set DH parameters P and G
  if (mbedtls_mpi_read_binary(&dhm.P, p, 192) != 0 ||
      mbedtls_mpi_read_binary(&dhm.G, g, 1) != 0) {
    mbedtls_dhm_free(&dhm);
    return false;
  }

  // Generate public key
  if (mbedtls_dhm_make_public(&dhm, (int)priv_key_len, pub_key, pub_key_len, NULL, NULL) != 0) {
    mbedtls_dhm_free(&dhm);
    return false;
  }

  // Read peer's public key
  if (mbedtls_dhm_read_public(&dhm, pub_key, pub_key_len) != 0) {
    mbedtls_dhm_free(&dhm);
    return false;
  }

  // Derive shared secret
  if (mbedtls_dhm_calc_secret(&dhm, secret_key, &secret_key_len, NULL, NULL) != 0) {
    mbedtls_dhm_free(&dhm);
    return false;
  }

  mbedtls_dhm_free(&dhm);
  return true;
}

void calculate_e_hashes(const uint8_t *shared_secret, const uint8_t *pke, const uint8_t *pkr,
                        const uint8_t *auth_key, uint8_t *e_hash1, uint8_t *e_hash2) {
  uint8_t data[192 * 2];
  memcpy(data, pke, 192);
  memcpy(data + 192, pkr, 192);

  hmac_sha256(auth_key, 32, data, 192 * 2, e_hash1);
  hmac_sha256(auth_key, 32, e_hash1, 32, e_hash2);
}

void derive_auth_key(const uint8_t *shared_secret, uint8_t *auth_key) {
  const char *personalization_string = "WPS-PIN";
  hmac_sha256(shared_secret, 32, (const uint8_t *)personalization_string, strlen(personalization_string), auth_key);
}
