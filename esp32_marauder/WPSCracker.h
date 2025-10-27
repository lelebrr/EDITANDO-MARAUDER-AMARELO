#ifndef WPSCRACKER_H
#define WPSCRACKER_H

#include <Arduino.h>

class WPSCracker {
public:
    WPSCracker();
    bool pixieDustAttack(uint8_t *m1, uint8_t *m2, uint8_t *m3, String &pin, String manufacturer);
    bool onlineBruteWPS(uint8_t *bssid, String &pin);
private:
    bool checkWPSChecksum(int pin);
    void derivePixieKey(int pin, uint8_t *pub_key, uint8_t *nonce, uint8_t *derived);
};

#endif
