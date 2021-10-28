#ifndef WIFI_LOG_H
#define WIFI_LOG_H

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

#define WIFI_LOG_FATAL(...)   do { printf("FATAL: "__VA_ARGS__ ); } while(0)
#define WIFI_LOG_ERROR(...)   do { printf("ERROR: "__VA_ARGS__ ); } while(0)
#define WIFI_LOG_WARN(...)    do { printf("WARN: "__VA_ARGS__  ); } while(0)
#define WIFI_LOG_NOTICE(...)  do { printf("NOTICE: "__VA_ARGS__); } while(0)
#define WIFI_LOG_INFO(...)    do { printf("INFO: "__VA_ARGS__  ); } while(0)
#define WIFI_LOG_DEBUG(...)   do { printf("DEBUG: "__VA_ARGS__ ); } while(0)
#define WIFI_LOG_TRACE(...)   do { printf("TRACE: "__VA_ARGS__ ); } while(0)

#endif

#endif