#ifndef WPSCRACKER_H
#define WPSCRACKER_H

#include <Arduino.h>

class WPSCracker {
public:
    WPSCracker();
    bool pixieDustAttack(uint8_t *m1, size_t m1_len, uint8_t *m2, size_t m2_len, uint8_t *m3, size_t m3_len, String &pin, String manufacturer);
    bool onlineBruteWPS(uint8_t *bssid, String &pin);
private:
    bool checkWPSChecksum(int pin);
    void derivePixieKey(int pin, uint8_t *pub_key, uint8_t *nonce, uint8_t *derived);
};

#endif
