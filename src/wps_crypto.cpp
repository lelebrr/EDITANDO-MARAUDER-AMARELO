#include "wps_crypto.h"
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/dhm.h>

// --- DH Globals ---
static mbedtls_dhm_context dhm;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static uint8_t pub_key[192];
static uint8_t priv_key[96];

static void add_tlv(uint8_t **buf, uint16_t type, uint16_t len, const void *value) {
    uint8_t *p = *buf;
    p[0] = (type >> 8) & 0xFF;
    p[1] = type & 0xFF;
    p[2] = (len >> 8) & 0xFF;
    p[3] = len & 0xFF;
    memcpy(p + 4, value, len);
    *buf += 4 + len;
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, key, key_len);
    mbedtls_sha256_update(&ctx, data, data_len);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

int build_m1(uint8_t *m1, int max_len, const uint8_t *bssid, const char *pin, uint8_t *auth_key) {
    // This is a simplified M1 for brute force. Real M1 is more complex.
    uint8_t *p = m1;
    uint8_t version = 0x10;
    uint8_t msg_type = 0x04; // M1
    uint8_t uuid[16] = {0};
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);

    add_tlv(&p, 0x104A, 1, &version); // Version
    add_tlv(&p, 0x1022, 1, &msg_type); // Message Type
    add_tlv(&p, 0x1047, 16, uuid);     // UUID
    add_tlv(&p, 0x1020, 6, mac);       // MAC Address
    // ... other attributes would go here in a real M1 ...

    return p - m1;
}

int build_m3(uint8_t *m3, int max_len, const uint8_t *bssid, const char *pin, const uint8_t *auth_key, const uint8_t *e_nonce, const uint8_t *s_nonce) {
    // This is a simplified M3 for brute force.
    uint8_t *p = m3;
    uint8_t version = 0x10;
    uint8_t msg_type = 0x08; // M3

    add_tlv(&p, 0x104A, 1, &version);
    add_tlv(&p, 0x1022, 1, &msg_type);
    // ... other attributes ...

    return p - m3;
}

int build_m5(uint8_t *m5, int max_len, const uint8_t *bssid, const uint8_t *auth_key, const uint8_t *e_nonce, const uint8_t *s_nonce) {
    // Simplified M5
    uint8_t *p = m5;
    uint8_t version = 0x10;
    uint8_t msg_type = 0x0C; // M5

    add_tlv(&p, 0x104A, 1, &version);
    add_tlv(&p, 0x1022, 1, &msg_type);

    return p - m5;
}

int build_m7(uint8_t *m7, int max_len, const uint8_t *bssid, const uint8_t *auth_key, const uint8_t *e_nonce, const uint8_t *s_nonce) {
    // Simplified M7
    uint8_t *p = m7;
    uint8_t version = 0x10;
    uint8_t msg_type = 0x0E; // M7

    add_tlv(&p, 0x104A, 1, &version);
    add_tlv(&p, 0x1022, 1, &msg_type);

    return p - m7;
}
