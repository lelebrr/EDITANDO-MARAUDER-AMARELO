#ifndef WPS_CRYPTO_H
#define WPS_CRYPTO_H

#include "Arduino.h"

int build_m1(uint8_t *m1, int max_len, const uint8_t *bssid, const char *pin, uint8_t *auth_key);
int build_m3(uint8_t *m3, int max_len, const uint8_t *bssid, const char *pin, const uint8_t *auth_key, const uint8_t *e_nonce, const uint8_t *s_nonce);
int build_m5(uint8_t *m5, int max_len, const uint8_t *bssid, const uint8_t *auth_key, const uint8_t *e_nonce, const uint8_t *s_nonce);
int build_m7(uint8_t *m7, int max_len, const uint8_t *bssid, const uint8_t *auth_key, const uint8_t *e_nonce, const uint8_t *s_nonce);

#endif // WPS_CRYPTO_H
