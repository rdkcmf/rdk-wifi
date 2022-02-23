#include "wifi_common_hal.h"
#include "wifi_client_hal.h"

#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

static void wifi_assert(int wifi_status, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

static int wifi_connection_callback(int ssid_index, char *ssid, wifiStatusCode_t *error);

int main()
{
  int wifi_status = 0;

  wifi_halConfig_t conf;
  strcpy(conf.wlan_Interface, "wlan1");

  wifi_status = wifi_initWithConfig(&conf);
  wifi_assert(wifi_status, "wifi_initWithSettings:%s", conf.wlan_Interface);
  wifi_connectEndpoint_callback_register(&wifi_connection_callback);

  wifi_status = wifi_connectEndpoint(0, "SSID_NAME", WIFI_SECURITY_WPA2_PSK_AES,
    NULL, "asdf123", NULL, 0, NULL, NULL, NULL, NULL);

  wifi_assert(wifi_status, "wifi_connectEndpoint");

  while (true)
    sleep(1);

  wifi_status = wifi_uninit();
  wifi_assert(wifi_status, "wifi_uninit");

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

int wifi_connection_callback(int ssid_index, char *ssid, wifiStatusCode_t *error)
{
  printf("ssid_index: %d\n", ssid_index);
  printf("ssid      : %s\n", ssid);
  printf("status    : %d\n", *error);
  return 0;
}
