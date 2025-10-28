#ifndef PACKETS_H
#define PACKETS_H

#include "Arduino.h"

// Basic structure for an 802.11 frame
struct ieee80211_frame {
  uint8_t frame_control[2];
  uint8_t duration[2];
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint8_t seq_ctrl[2];
  uint8_t body[0];
};

// Structure for a WPS M1 message
struct wps_m1_packet {
  struct ieee80211_frame hdr;
  uint8_t wps_data[256]; // Placeholder for WPS data
  int len;
};

// Structure for a WPS M2 message
struct wps_m2_packet {
  struct ieee80211_frame hdr;
  uint8_t wps_data[512]; // Placeholder for WPS data
  int len;
};

// Function to build a WPS M1 message
void build_wps_m1(struct wps_m1_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid);

// Structure for a WPS M3 message
struct wps_m3_packet {
  struct ieee80211_frame hdr;
  uint8_t wps_data[256];
  int len;
};

// Structure for a WPS M4 message
struct wps_m4_packet {
  struct ieee80211_frame hdr;
  uint8_t wps_data[512];
  int len;
};

// Function to build a WPS M3 message
void build_wps_m3(struct wps_m3_packet &pkt, const uint8_t *src_mac, const uint8_t *bssid, const char *pin, const uint8_t *pke, const uint8_t *pkr);

// Function to parse WPS Information Elements
const uint8_t *parse_wps_ie(const uint8_t *wps_ie, int wps_ie_len, uint16_t attr_id, uint16_t *attr_len);


#endif // PACKETS_H
