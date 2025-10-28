#include "WPSCracker.h"
#include "WiFiScan.h"
#include "esp_wifi.h"
#include "SD.h"
#include "wps_crypto.h"

extern WiFiScan wifi_scan_obj;
extern LinkedList<AccessPoint>* access_points;

// TODO: Implement the sniffer callback and capture functions

WPSCracker::WPSCracker() {}

void WPSCracker::scan() {
  if (display_cb) display_cb("A procurar redes WPS...");

  // Clear previous results
  aps.clear();

  // Start a scan for APs and Stations
  wifi_scan_obj.StartScan(WIFI_SCAN_AP_STA);

  // Wait for the scan to complete or timeout
  unsigned long start_time = millis();
  while ((access_points->size() < 10) && (millis() - start_time < 10000)) {
    delay(100);
  }

  wifi_scan_obj.StopScan(WIFI_SCAN_AP_STA);

  if (display_cb) display_cb("Scan concluído. A filtrar...");

  // Filter for WPS-enabled APs
  for (int i = 0; i < access_points->size(); i++) {
    AccessPoint ap = access_points->get(i);
    if (ap.wps) {
      aps.push_back(ap);
    }
  }

  if (display_cb) {
    String msg = "Encontradas ";
    msg += aps.size();
    msg += " redes WPS.";
    display_cb(msg);
  }
}

void WPSCracker::attack(int index) {
  if (index < 0 || index >= aps.size()) {
    if (display_cb) display_cb("Índice de AP inválido.");
    return;
  }

  AccessPoint ap = aps[index];
  String pin;

  if (display_cb) {
    String msg = "A atacar " + ap.essid + "...";
    display_cb(msg);
  }

  // Try Pixie Dust attack first
  if (display_cb) display_cb("A tentar ataque Pixie Dust...");
  if (pixieDust(ap, pin)) {
    if (display_cb) {
      String msg = "Sucesso do Pixie Dust!\nPIN: " + pin;
      display_cb(msg);
    }
    savePin(ap.essid, pin, ap.bssid);
    return;
  }

  // If Pixie Dust fails, fall back to brute force
  if (display_cb) display_cb("Pixie Dust falhou. A tentar Força Bruta...");
  if (bruteForce(ap, pin)) {
    if (display_cb) {
      String msg = "Sucesso da Força Bruta!\nPIN: " + pin;
      display_cb(msg);
    }
    savePin(ap.essid, pin, ap.bssid);
  } else {
    if (display_cb) display_cb("O ataque falhou.");
  }
}

void WPSCracker::setDisplayCallback(void (*callback)(const String&)) {
  display_cb = callback;
}

void WPSCracker::setProgressCallback(void (*callback)(int)) {
  progress_cb = callback;
}

bool WPSCracker::pixieDust(AccessPoint &ap, String &pin) {
  // Ensure WiFi is in a suitable mode (AP or STA with promiscuous) before calling this.

  // 1. Set channel
  esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);

  // 2. Build and send M1
  struct wps_m1_packet m1;
  uint8_t src_mac[6];
  esp_wifi_get_mac(WIFI_IF_AP, src_mac);
  build_wps_m1(m1, src_mac, ap.bssid);
  sendRaw((uint8_t*)&m1, m1.len);

  // 3. Capture M2
  uint8_t m2_buf[512];
  int m2_len = 0;
  if (!captureM2(m2_buf, m2_len)) {
    return false;
  }

  // TODO: 4. Parse M2 and 5. Crack PIN
  // This is where the M2 packet would be parsed to extract PKE, PKR, E-Hash1, E-Hash2, and E-Nonce.
  // Then, the cryptographic functions in wps_crypto would be used to derive the key and crack the PIN.
  // This is a complex process that requires a deep understanding of the WPS protocol and cryptography.
  // For now, this is a placeholder.

  return false; // Placeholder
}

bool WPSCracker::bruteForce(AccessPoint &ap, String &pin) {
  // Ensure WiFi is in a suitable mode (AP or STA with promiscuous) before calling this.

  // 1. Set channel
  esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);

  for (int i = 0; i <= 9999; i++) {
    char pin_str[9];
    // This is a simplified PIN generation for the first half.
    // A real attack would be more systematic.
    sprintf(pin_str, "%04d", i);

    // M1-M4 exchange for first half of PIN
    // TODO: Implement the M1-M4 exchange here.
    // This would involve building and sending M1, capturing M2, building and sending M3,
    // and capturing M4. The M4 response would then be checked to see if the first half
    // of the PIN is correct.
    if (display_cb) display_cb("A testar a primeira metade do PIN: " + String(pin_str));

    unsigned long start_time = millis();
    while(millis() - start_time < 100) {
      // Non-blocking delay
    }

    if (progress_cb) progress_cb((i*100)/10000);
  }

  return false; // Placeholder
}

bool WPSCracker::checkWPSChecksum(int pin) {
  int accum = 0;
  int temp_pin = pin;
  while (temp_pin > 0) {
    accum += 3 * (temp_pin % 10);
    temp_pin /= 10;
    accum += temp_pin % 10;
    temp_pin /= 10;
  }
  return (accum % 10) == 0;
}

void WPSCracker::savePin(String ssid, String pin, uint8_t *bssid) {
  if (!SD.begin()) {
    if (display_cb) display_cb("Cartão SD não encontrado.");
    return;
  }

  String filename = "/wps_pins.txt";
  File file = SD.open(filename, FILE_APPEND);
  if (!file) {
    if (display_cb) display_cb("Falha ao abrir o ficheiro.");
    return;
  }

  char bssid_str[18];
  sprintf(bssid_str, "%02X:%02X:%02X:%02X:%02X:%02X",
          bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

  file.println("SSID: " + ssid);
  file.println("BSSID: " + String(bssid_str));
  file.println("PIN: " + pin);
  file.println("--------------------");
  file.close();

  if (display_cb) display_cb("PIN guardado em " + filename);
}

void WPSCracker::sendRaw(uint8_t *pkt, int len) {
  esp_wifi_80211_tx(WIFI_IF_AP, pkt, len, false);
}

// Global buffer for M2 packet
static uint8_t m2_buf[512];
static int m2_len = 0;
static bool m2_captured = false;

// Sniffer callback to capture M2 packet
static void wps_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  if (pkt->payload[0] == 0x50) { // Probe Response
    // A simple check for M2 (highly simplistic)
    if (pkt->rx_ctrl.sig_len > 100) {
      memcpy(m2_buf, pkt->payload, pkt->rx_ctrl.sig_len);
      m2_len = pkt->rx_ctrl.sig_len;
      m2_captured = true;
    }
  }
}

bool WPSCracker::captureM2(uint8_t *buf, int &len) {
  m2_captured = false;
  esp_wifi_set_promiscuous_rx_cb(wps_sniffer_callback);

  unsigned long start_time = millis();
  while (!m2_captured && (millis() - start_time < 3000)) { // 3s timeout
    delay(100);
  }

  if (m2_captured) {
    memcpy(buf, m2_buf, m2_len);
    len = m2_len;
  }

  return m2_captured;
}

// Global buffer for M4 packet
static uint8_t m4_buf[512];
static int m4_len = 0;
static bool m4_captured = false;

// Sniffer callback to capture M4 packet
static void wps_m4_sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  // A simple check for M4 (highly simplistic)
  if (pkt->payload[0] == 0x08 && pkt->rx_ctrl.sig_len > 100) {
    memcpy(m4_buf, pkt->payload, pkt->rx_ctrl.sig_len);
    m4_len = pkt->rx_ctrl.sig_len;
    m4_captured = true;
  }
}

bool WPSCracker::captureM4(uint8_t *buf, int &len) {
  m4_captured = false;
  esp_wifi_set_promiscuous_rx_cb(wps_m4_sniffer_callback);

  unsigned long start_time = millis();
  while (!m4_captured && (millis() - start_time < 3000)) { // 3s timeout
    delay(100);
  }

  if (m4_captured) {
    memcpy(buf, m4_buf, m4_len);
    len = m4_len;
  }

  return m4_captured;
}
