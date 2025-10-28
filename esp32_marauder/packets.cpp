#include "packets.h"
#include <string.h>
#include "wps_crypto.h"

// Helper function to add a TLV attribute to a buffer
static int add_tlv(uint8_t *buf, uint16_t type, uint16_t len, const void *value) {
  buf[0] = (type >> 8) & 0xFF;
  buf[1] = type & 0xFF;
  buf[2] = (len >> 8) & 0xFF;
  buf[3] = len & 0xFF;
  memcpy(buf + 4, value, len);
  return len + 4;
}

void build_wps_m1(struct wps_m1_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid) {
  // Frame control: Probe Request
  pkt.hdr.frame_control[0] = 0x40;
  pkt.hdr.frame_control[1] = 0x00;

  // Duration
  pkt.hdr.duration[0] = 0x00;
  pkt.hdr.duration[1] = 0x00;

  // Set MAC addresses
  memcpy(pkt.hdr.addr1, bssid, 6); // Destination
  memcpy(pkt.hdr.addr2, src_mac, 6); // Source
  memcpy(pkt.hdr.addr3, bssid, 6); // BSSID

  // Sequence control
  pkt.hdr.seq_ctrl[0] = 0x00;
  pkt.hdr.seq_ctrl[1] = 0x00;

  // WPS Information Element
  uint8_t wps_ie[] = {
    0xdd, 0x8a, 0x00, 0x50, 0xf2, 0x04,
    0x10, 0x4a, 0x00, 0x01, 0x10,
    0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20,
    0x10, 0x08, 0x00, 0x02, 0x00, 0x88,
    0x10, 0x47, 0x00, 0x10,
    'E', 'S', 'P', '3', '2', '_', 'M', 'a', 'r', 'a', 'u', 'd', 'e', 'r', '!', '!',
    0x10, 0x21, 0x00, 0x0f,
    'E', 'S', 'P', 'R', 'E', 'S', 'S', 'I', 'F', ' ', 'I', 'N', 'C', '.', ' ',
    0x10, 0x23, 0x00, 0x08,
    'E', 'S', 'P', '3', '2', 'A', 'P', ' ',
    0x10, 0x24, 0x00, 0x04,
    '0', '0', '0', '0',
    0x10, 0x42, 0x00, 0x01, 0x00,
    0x10, 0x41, 0x00, 0x01, 0x01,
    0x10, 0x3b, 0x00, 0x01, 0x03,
    0x10, 0x11, 0x00, 0x08,
    'E', 'S', 'P', '3', '2', 'A', 'P', ' ',
    0x10, 0x12, 0x00, 0x04,
    '1', '2', '3', '4',
    0x10, 0x0e, 0x00, 0x08, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
    0x10, 0x09, 0x00, 0x01, 0x00,
    0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01,
    0x10, 0x20, 0x00, 0x06,
    0x00, 0x50, 0xf2, 0x04, 0x00, 0x01,
    0x10, 0x08, 0x00, 0x02, 0x00, 0x8c,
  };

  memcpy(pkt.wps_data, wps_ie, sizeof(wps_ie));
  pkt.len = sizeof(struct ieee80211_frame) + sizeof(wps_ie);
}

void build_wps_m3(struct wps_m3_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid, const char *pin, const uint8_t *pke, const uint8_t *pkr, const uint8_t *r_nonce) {
  uint8_t *buf = pkt.wps_data;
  int len = 0;

  uint8_t version = 0x10;
  len += add_tlv(buf + len, 0x104A, 1, &version);

  uint8_t msg_type = 0x08; // M3
  len += add_tlv(buf + len, 0x1022, 1, &msg_type);

  uint8_t e_nonce[16];
  for (int i = 0; i < 16; i++) e_nonce[i] = esp_random();
  len += add_tlv(buf + len, 0x101A, 16, e_nonce);

  len += add_tlv(buf + len, 0x1039, 16, r_nonce);

  // E-Hash1 and E-Hash2
  uint8_t auth_key[32];
  uint8_t shared_secret[192]; // Placeholder, should be derived from DH
  derive_auth_key(shared_secret, auth_key);
  uint8_t e_hash1[32], e_hash2[32];
  calculate_e_hashes(shared_secret, pke, pkr, auth_key, e_hash1, e_hash2);
  len += add_tlv(buf + len, 0x1014, 32, e_hash1);
  len += add_tlv(buf + len, 0x1015, 32, e_hash2);

  pkt.len = len;
}

void build_wps_m5(struct wps_m5_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid, const char *pin, const uint8_t *pke, const uint8_t *pkr, const uint8_t *r_nonce) {
  // Placeholder
  pkt.len = 0;
}

void build_wps_m7(struct wps_m7_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid, const char *pin, const uint8_t *pke, const uint8_t *pkr, const uint8_t *r_nonce) {
  // Placeholder
  pkt.len = 0;
}

const uint8_t *parse_wps_ie(const uint8_t *wps_ie, int wps_ie_len, uint16_t attr_id, uint16_t *attr_len) {
  int i = 0;
  while (i < wps_ie_len) {
    uint16_t current_attr_id = (wps_ie[i] << 8) | wps_ie[i + 1];
    uint16_t current_attr_len = (wps_ie[i + 2] << 8) | wps_ie[i + 3];

    if (current_attr_id == attr_id) {
      if (attr_len) {
        *attr_len = current_attr_len;
      }
      return &wps_ie[i + 4];
    }

    i += 4 + current_attr_len;
  }

  return NULL;
}
