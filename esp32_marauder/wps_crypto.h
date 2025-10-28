#ifndef WPS_CRYPTO_H
#define WPS_CRYPTO_H

#include "Arduino.h"

// Function to compute HMAC-SHA256
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out);

// Function to compute SHA256
void sha256(const uint8_t *data, size_t data_len, uint8_t *out);

// Function for AES-128 ECB encryption
void aes_128_ecb_encrypt(const uint8_t *key, const uint8_t *data, uint8_t *out);

// Function for Diffie-Hellman key exchange
bool diffie_hellman(const uint8_t *p, const uint8_t *g,
                    const uint8_t *priv_key, size_t priv_key_len,
                    uint8_t *pub_key, size_t &pub_key_len,
                    uint8_t *secret_key, size_t &secret_key_len);

// Function to calculate E-Hash1 and E-Hash2
void calculate_e_hashes(const uint8_t *shared_secret, const uint8_t *pke, const uint8_t *pkr,
                        const uint8_t *auth_key, uint8_t *e_hash1, uint8_t *e_hash2);

#endif // WPS_CRYPTO_H
