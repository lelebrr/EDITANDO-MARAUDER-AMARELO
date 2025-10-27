#include "Display.h"

Display display;

void setup() {
  Serial.begin(115200);
  display.RunSetup();

  display.main(WIFI_SCAN_PWN);
}

void loop() {
  delay(10);
}
