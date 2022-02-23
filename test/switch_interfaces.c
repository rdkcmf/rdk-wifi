#include "wifi_common_hal.h"
#include "wifi_client_hal.h"

#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

static void wifi_neightListFree(wifi_neighbor_ap_t * bss)
{
  if (bss)
    free(bss);
}

static void wifi_assert(int wifi_status, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

#define NWLAN_IFACES 2

static char *wlan_iface_list[NWLAN_IFACES] = {
  "wlx984827474ec9",
  "wlan1"
};

int main()
{
  int iface_idx = 0;
  uint32_t bss_count = 0;
  wifi_neighbor_ap_t *bss_list = NULL;

  while (true) {
    int wifi_status = 0;

    wifi_halConfig_t conf;
    strcpy(conf.wlan_Interface, wlan_iface_list[iface_idx++]);
    if (iface_idx == NWLAN_IFACES)
      iface_idx = 0;

    wifi_status = wifi_initWithConfig(&conf);
    wifi_assert(wifi_status, "wifi_initWithSettings:%s", conf.wlan_Interface);

    wifi_status = wifi_getNeighboringWiFiDiagnosticResult(0, &bss_list, &bss_count);
    wifi_assert(wifi_status, "wifi_getNeighboringWiFiDiagnosticResult");

    wifi_neightListFree(bss_list);
    wifi_status = wifi_uninit();
    wifi_assert(wifi_status, "wifi_uninit");

    sleep(3);
  }

  return 0;
}

void wifi_assert(int wifi_status, const char *format, ...)
{
  if (wifi_status != 0) {
    va_list arg_list;
    va_start(arg_list, format);
    vfprintf(stderr, format, arg_list);
    va_end(arg_list);
    fprintf(stderr, "\twifi_status:%d\n", wifi_status);
    abort();
  }
}
