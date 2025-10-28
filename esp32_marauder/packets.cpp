#include "packets.h"
#include <string.h>
#include "wps_crypto.h"

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

void build_wps_m3(struct wps_m3_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid, const char *pin, const uint8_t *pke, const uint8_t *pkr) {
  // This is a placeholder and needs to be fully implemented
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
