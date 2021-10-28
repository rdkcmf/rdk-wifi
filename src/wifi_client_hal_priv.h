#ifndef WIFI_CLIENT_HAL_PRIV_H
#define WIFI_CLIENT_HAL_PRIV_H

#ifdef __cplusplus 
extern "C" {
#endif

#ifndef INT
#define INT   int
#endif

extern wifi_neighbor_ap_t ap_list[512];
extern uint32_t ap_count;
INT parse_scan_results(char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif