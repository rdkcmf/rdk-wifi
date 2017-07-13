/*
 * If not stated otherwise in this file or this component's License file
 * the following copyright and licenses apply:
 *
 * Copyright 2017 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef __WIFI_HAL_PRIV_H__
#define __WIFI_HAL_PRIV_H__

#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>

#ifdef WPA_SUPPLICANT
#include <wpa_ctrl.h>
#endif

#define MODULE_NAME		"WIFI-HAL"
#define WPA_SUPL_CONF		"/opt/wifi/wpa_supplicant.conf"
#define WPA_SUPL_PIDFILE	"/var/run/wpa_supplicant/wlan0.pid"
#define WPA_SUPL_CTRL		"/var/run/wpa_supplicant/wlan0"

#define ENABLE_MEM_PSK		1	/*Enable storing PSK only in memory*/
#define DISABLE_MEM_PSK		0
#define ENABLE_CONFIG_UPDATE	1	/*Enable update of configuration file*/
#define DISABLE_CONFIG_UPDATE	0

#define WPA_SUP_CMD_FAILED	-1	/*Return value in case WPA command failed*/
#define WPA_SUP_CMD_TIMEOUT	-2	/*Return value in case WPA command timed out*/
#define WPA_SUP_CMD_INIT_ERR	-3	/*Return value in case wifi_init is not done*/

#define BUF_SIZE                256
#define WPA_SUP_TIMEOUT         500000   /* 500 msec */
#define WPA_SUP_CMD_MAX		512	/* Maximum command size that can be sent to wpa supplicant*/
#define MAX_AP_SUPPORTED	100	/* Maximum APs that can be parsed */
/*Debug related*/
#define WIFI_HAL_DEBUG 1
#ifdef WIFI_HAL_DEBUG
#define wifi_hal_dbg wifi_hal_msg
#else
#define wifi_hal_dbg if(0)
#endif
/*Utility*/
#define NULL_STRING(s) (s && (s[0]=='\0'))
#define UNUSED_VAR(v) (void)(v)
#define API_NOT_IMPLEMENTED	{ \
	printf("%s: API Not implemented yet\n",__func__); \
	return RETURN_OK; \
}

#define G_WIFI_MUTEX_LOCK(lck) { \
   wifi_hal_dbg("%s <=> Waiting lock <=> held by:%s\n",__func__,g_wifi.lock_owner);\
   pthread_mutex_lock(lck); \
   wifi_hal_dbg("New lock acquired by :%s\n",__func__);\
   strcpy(g_wifi.lock_owner, __func__); \
}

/*with a default timeout of 2 sec*/
#define G_WIFI_MUTEX_TIMEDLOCK(lck, rv) { \
   int attempts=10; \
   wifi_hal_dbg("%s <=> Waiting lock <=> held by:%s\n",__func__,g_wifi.lock_owner);\
   while(pthread_mutex_trylock(lck)!=0) { \
      if(--attempts<=0) { \
         wifi_hal_dbg("%s: giving up on trylock\n",__func__); \
         rv=-EBUSY; \
      } \
      usleep(200000); \
   } \
   if(rv!=-EBUSY){ \
      wifi_hal_dbg("New lock acquired by :%s\n",__func__);\
      strcpy(g_wifi.lock_owner, __func__); \
   } \
}

#define G_WIFI_MUTEX_UNLOCK(lck) { \
   wifi_hal_dbg("Released lock: %s\n",g_wifi.lock_owner);\
   g_wifi.lock_owner[0]='\0'; \
   pthread_mutex_unlock(lck); \
}

typedef enum {
    WIFI_HAL_SCAN_STATE_IDLE,
    WIFI_HAL_SCAN_STATE_CMD_SENT,
    WIFI_HAL_SCAN_STATE_STARTED,
    WIFI_HAL_SCAN_STATE_RESULTS_RECEIVED,
} WIFI_HAL_SCAN_STATE;

typedef struct _g_wifi_vars {
    BOOL init_done;				/* To make sure whether WiFi initialization was already done.*/
    BOOL stop_monitor;				/* To stop the monitor thread asynchronously. */
    BOOL kill_wpa_supplicant;			/* Flag to kill wpa_supplicant */

    uint32_t sup_pid;				/* Keeps track of wpa supplicant daemon PID*/
    pthread_mutex_t sup_lock;			/* mutex lock for wpa supplicant calls*/
    char lock_owner[128];
    struct wpa_ctrl *ctrl_handle;		/* handle that contains control interface*/
    struct wpa_ctrl *monitor_handle; 		/* handle that contains monitor interface*/
    WIFI_HAL_SCAN_STATE cur_scan_state;		/* Current WPA Scanning state*/
    wifi_neighbor_ap_t ap_list[MAX_AP_SUPPORTED]; /*Maximum number of APs that can be parsed/stored.*/

    char update_ssid_info;	  	/* Whether current SSID information need to be persisted, required when connected to a new AP*/
    int persist_ssid_enabled;     	/* Whether we want to save SSID information to configuration file: 1=save, 0=don'tsave */ 
}WIFI_HAL_GLOBAL;

char* parse_token(char *input, char *keyword, const char *delim);
int send_wpa_cli_command(char *reply, size_t reply_len, char *cmd, ...);

void* wifi_event_monitor_thread(void *param);

int update_wpa_configuration(int factory_reset, int mem_only_psk, int update_config);
void wifi_hal_msg(const char *format, ...);
void wifi_hal_reset_data(void);
#endif
