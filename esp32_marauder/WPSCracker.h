#ifndef WPSCRACKER_H
#define WPSCRACKER_H

#include "Arduino.h"
#include <vector>
#include "WiFiScan.h"

class WPSCracker {
public:
  WPSCracker();
  void scan();
  void attack(int index);
  void setDisplayCallback(void (*callback)(const String&));
  void setProgressCallback(void (*callback)(int));

  std::vector<AccessPoint> aps;

private:
  void (*display_cb)(const String&) = nullptr;
  void (*progress_cb)(int) = nullptr;

  bool pixieDust(AccessPoint &ap, String &pin);
  bool bruteForce(AccessPoint &ap, String &pin);
  bool checkWPSChecksum(int pin);
  void savePin(String ssid, String pin, uint8_t *bssid);
  void sendRaw(uint8_t *pkt, int len);
  bool captureM2(uint8_t *buf, int &len);
  bool captureM4(uint8_t *buf, int &len);
};

#endif // WPSCRACKER_H
