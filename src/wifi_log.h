#ifndef WIFI_LOG_H
#define WIFI_LOG_H

#define WLAN_PATHMAX 128

typedef struct wifi_context {
  wifi_halConfig_t conf;
  char ctrl_path[WLAN_PATHMAX];
} wifi_context_t;

#ifdef WITH_RDKLOGGER

#include "rdk_debug.h"

#define WIFI_LOG_MODULE "LOG.RDK.WIFIHAL"

#define WIFI_LOG_FATAL(...)   do { RDK_LOG(RDK_LOG_FATAL,  WIFI_LOG_MODULE, __VA_ARGS__); } while(0)
#define WIFI_LOG_ERROR(...)   do { RDK_LOG(RDK_LOG_ERROR,  WIFI_LOG_MODULE, __VA_ARGS__); } while(0)
#define WIFI_LOG_WARN(...)    do { RDK_LOG(RDK_LOG_WARN,   WIFI_LOG_MODULE, __VA_ARGS__); } while(0)
#define WIFI_LOG_NOTICE(...)  do { RDK_LOG(RDK_LOG_NOTICE, WIFI_LOG_MODULE, __VA_ARGS__); } while(0)
#define WIFI_LOG_INFO(...)    do { RDK_LOG(RDK_LOG_INFO,   WIFI_LOG_MODULE, __VA_ARGS__); } while(0)
#define WIFI_LOG_DEBUG(...)   do { RDK_LOG(RDK_LOG_DEBUG,  WIFI_LOG_MODULE, __VA_ARGS__); } while(0)
#define WIFI_LOG_TRACE(...)   do { RDK_LOG(RDK_LOG_TRACE1, WIFI_LOG_MODULE, __VA_ARGS__); } while(0)

#else

void wifi_printf(const char *level, const char *format, ...) __attribute__((format(printf, 2, 3)));

#define WIFI_LOG_FATAL(format, ...)   wifi_printf("FATAL", format, ##  __VA_ARGS__ )
#define WIFI_LOG_ERROR(format, ...)   wifi_printf("ERROR", format, ## __VA_ARGS__)
#define WIFI_LOG_WARN(format, ...)    wifi_printf("WARN", format, ## __VA_ARGS__)
#define WIFI_LOG_NOTICE(format, ...)  wifi_printf("NOTICE", format, ## __VA_ARGS__)
#define WIFI_LOG_INFO(format, ...)    wifi_printf("INFO", format, ## __VA_ARGS__)
#define WIFI_LOG_DEBUG(format, ...)   wifi_printf("DEBUG", format, ## __VA_ARGS__)
#define WIFI_LOG_TRACE(format, ...)   wifi_printf("TRACE", format, ## __VA_ARGS__)

#endif

#endif
