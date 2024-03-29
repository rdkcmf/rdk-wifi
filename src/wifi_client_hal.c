/*
* If not stated otherwise in this file or this component's Licenses.txt file the
* following copyright and licenses apply:
*
* Copyright 2018 RDK Management
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <wifi_client_hal.h>
#include <unistd.h>
#include <pthread.h>
#include "wifi_log.h"
#ifdef WIFI_CLIENT_ROAMING
#include <errno.h>
#include "cJSON.h"
#endif
#include <stdarg.h>
#include <sys/time.h>
//This call back will be invoked when client automatically connect to AP.

wifi_connectEndpoint_callback callback_connect = NULL;

//This call back will be invoked when client lost the connection to AP.
wifi_disconnectEndpoint_callback callback_disconnect;

#include <wpa_ctrl.h>

#include <stdint.h>
typedef uint8_t u8;
// added to be able to use wpa_supplicant's 'printf_decode' utility function to decode the SSIDs encoded by wpa_supplicant
extern size_t printf_decode(u8 *buf, size_t maxlen, const char *str);

#define WPA_SUP_TIMEOUT     5000         /* 5 msec */
#define MAX_SSID_LEN        32           /* Maximum SSID name */
#define MAX_PASSWORD_LEN    64           /* Maximum password length */
#define ENET_LEN            17           /* Length of bytes for displaying an Ethernet address, e.g., 00:00:00:00:00:00.*/
#define CSPEC_LEN           20           /* Channel Spec string length */
#define RETURN_BUF_LENGTH   (96*1024)         /* Return buffer length */
#define BUFF_LEN_32         MAX_SSID_LEN /* Buffer Length 32 */
#define BUFF_LEN_64         64           /* Buffer Length 64*/
#define MAX_WPS_AP_COUNT    5            /* Max number of PBC enabled Access Points */
#define WPS_CON_TIMEOUT     120          /* WPS connection timeout */

#define MAX_NEIGHBOR_LIMIT  32            /* Max number of APs in neighbor report */
#define PREVIOUS_AUTH_INVALID 2           /* Previous authentication no longer valid reason code */
#ifdef WIFI_CLIENT_ROAMING
#define WIFI_ROAMING_CONFIG_FILE "/opt/secure/wifi/wifi_roamingControl.json"  /* Persistent storage for Roaming Configuration */
#define WIFI_DEFAULT_ROAMING_ENABLE false
#define WIFI_DEFAULT_PRE_ASSN_BEST_THRLD -67
#define WIFI_DEFAULT_PRE_ASSN_BEST_DELTA 3
#define WIFI_DEFAULT_BEST_DELTA_CONNECTED   12
#define WIFI_DEFAULT_POST_ASSN_SELF_STEER_THRESHOLD  -75
#define WIFI_DEFAULT_POST_ASSN_SELF_STEER_TIMEFRAME  60
#define WIFI_DEFAULT_SELF_STEER_OVERRIDE_ENABLE false
#define WIFI_DEFAULT_BEST_DELTA_DISCONNECTED 8
#define WIFI_DEFAULT_AP_CONTROL_THRESHOLD -75
#define WIFI_DEFAULT_AP_CONTROL_TIMEFRAME 60
#define WIFI_DEFAULT_POST_ASSN_BACKOFF_TIME    2
#define WIFI_DEFAULT_POST_ASSN_DELTA    3
#define WPA_EVENT_BEACON_LOSS "CTRL-EVENT-BEACON-LOSS"
#define WIFI_MAX_POST_ASSN_BACKOFF_TIME 3600 /* Max back off timer(1 Hour) for Post Association Roaming */
#define WIFI_MAX_POST_ASSN_TIME_FRAME 36000  /* Max limit for Time frame (10 Hours) limit for Post Assoc timeFrame */
#endif


typedef enum {
    WIFI_HAL_WPA_SUP_STATE_IDLE,
    WIFI_HAL_WPA_SUP_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_CONNECTING,
} WIFI_HAL_WPA_SUP_STATE;

typedef enum {
    WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE,
    WIFI_HAL_WPA_SUP_SCAN_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED,
    WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED,
} WIFI_HAL_WPA_SUP_SCAN_STATE;

#ifdef WIFI_CLIENT_ROAMING
typedef enum {
    WIFI_HAL_ROAM_STATE_ROAMING_IDLE,
    WIFI_HAL_ROAM_STATE_SIGNAL_PROCESSING,
    WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_STARTED,
    WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_EXPIRED,
    WIFI_HAL_ROAM_STATE_AP_SELECTION,
    WIFI_HAL_ROAM_STATE_ROAMING_TRIGGERED,
    WIFI_HAL_ROAM_STATE_ROAMING_SUCCESS,
} WIFI_HAL_ROAM_STATE;

typedef enum {
    WIFI_HAL_RRM_NEIGHBOR_REP_STATE_IDLE,
    WIFI_HAL_RRM_NEIGHBOR_REP_RECEIVED,
    WIFI_HAL_RRM_NEIGHBOR_REP_REQUEST_FAILED,
    WIFI_HAL_RRM_NEIGHBOR_REP_STATE_INTERNAL_ERROR
} WIFI_HAL_RRM_NEIGHBOR_REP_STATUS;

typedef enum {
    WIFI_HAL_ROAMING_MODE_NOT_SET,
    WIFI_HAL_ROAMING_MODE_SELF_STEERING,
    WIFI_HAL_ROAMING_MODE_AP_STEERING,
} WIFI_HAL_ROAMING_MODE;

typedef struct _wifi_rrm_neighbor_rep_request_t
{
    char ssid[MAX_SSID_LEN + 1];
    int lci;
    int civic;
} wifi_rrm_neighbor_rep_request_t;

typedef struct _wifi_rrm_neighbor_ap_t
{
    char ssid[BUFF_LEN_32];
    char bssid[BUFF_LEN_32];
    char bssidInfo[BUFF_LEN_64];
    int op_class;
    int channel;
    int phy_type;
    int freq;
} wifi_rrm_neighbor_ap_t;

typedef struct _wifi_neighbor_report_t
{
    wifi_rrm_neighbor_ap_t neighbor_ap [MAX_NEIGHBOR_LIMIT];
    int neighbor_cnt;
} wifi_rrm_neighbor_report_t;
#endif

typedef struct _wifi_wps_pbc_ap
{
    CHAR ap_SSID[MAX_SSID_LEN+1];
    CHAR ap_BSSID[20];
    INT  ap_SignalStrength;
    INT  ap_Frequency;
    WIFI_HAL_FREQ_BAND ap_FreqBand;
} wifi_wps_pbc_ap_t;

/* The control and monitoring interface is defined and initialized during the init phase */
extern struct wpa_ctrl *g_wpa_ctrl;
extern struct wpa_ctrl *g_wpa_monitor;

/* This mutex is used around wpa_supplicant calls. This is defined and initialized during the init phase */
extern pthread_mutex_t wpa_sup_lock;

/* Use the same buffer from wifi_common_hal.c */
extern char cmd_buf[1024];                     /* Buffer to pass the commands into */
extern char return_buf[RETURN_BUF_LENGTH];                  /* Buffer that stores the return results */

extern wifi_neighbor_ap_t ap_list[512];
extern uint32_t ap_count;
INT parse_scan_results(char *buf, size_t len);

BOOL bNoAutoScan=FALSE;
char bUpdatedSSIDInfo=1;
BOOL bIsWpsCompleted = TRUE;
BOOL bIsPBCOverlapDetected = FALSE;
BOOL bWpsPBC = FALSE;
struct timespec timespec_wps_cancel;

/* Initialize the state of the supplicant */
WIFI_HAL_WPA_SUP_STATE cur_sup_state = WIFI_HAL_WPA_SUP_STATE_IDLE;
WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state_from_supp = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
extern WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state;

static char event_buf[4096];                   /* Buffer to store the event results */
bool stop_monitor;
static int isPrivateSSID=1;                  /* Variable to check whether to save to conf file - Default value is 1 (Will save to conf file) */
size_t event_buf_len;
pthread_t wps_start_thread;


#ifdef WIFI_CLIENT_ROAMING
pthread_mutex_t wifi_roam_lock;
pthread_cond_t cond;
wifi_rrm_neighbor_report_t stRrmNeighborRpt;
pthread_t wifi_signal_mon_thread;
wifi_roamingCtrl_t pstRoamingCtrl;        /* Global Roaming configuration */
int backOffRefreshed = 1;
INT postAssocBackOffTime = WIFI_DEFAULT_POST_ASSN_BACKOFF_TIME; 
WIFI_HAL_RRM_NEIGHBOR_REP_STATUS cur_rrm_nbr_rep_state = WIFI_HAL_RRM_NEIGHBOR_REP_STATE_IDLE;
//WIFI_HAL_ROAMING_MODE cur_roaming_mode = WIFI_HAL_ROAMING_MODE_SELF_STEERING;
WIFI_HAL_ROAMING_MODE cur_roaming_mode = WIFI_HAL_ROAMING_MODE_AP_STEERING;
WIFI_HAL_ROAM_STATE cur_roaming_state = WIFI_HAL_ROAM_STATE_ROAMING_IDLE;
#endif   // WIFI_CLIENT_ROAMING

INT is_null_pointer(char* str);

// Parse WPS-PBC enabled access points from Scan results
int parse_wps_pbc_accesspoints(char *buf,wifi_wps_pbc_ap_t ap_list[]);
// Start WPS operation with Band selection
void* start_wifi_wps_connection(void *param);
// Stop WPS operation on timeout
void stop_wifi_wps_connection();
// Check wether the station has dual band support
BOOL isDualBandSupported();
// Initiate WPS connection to athe given BSSID
int triggerWpsPush(char *bssid);

#ifdef WIFI_CLIENT_ROAMING
//  @brief This call will read the given file as argument
static char* readPersistentFile(char *fileName);
//  @brief this call writes the given json data to the given fileName as argument
static int writeToPersistentFile (char *fileName, cJSON *pRoamingCtrl_data);
// @brief store wifi roaming configurations to persistent file
int persist_roaming_config(wifi_roamingCtrl_t*);
// @brief start wifi signal monitor thread for continues signal monitoring.
void start_wifi_signal_monitor_timer(void *arg);

#endif

char ssid_to_find[MAX_SSID_LEN+1] = {0};
char scanned_ssid[MAX_SSID_LEN+1] = {0};

//This call back will be invoked when client automatically connect to AP.
wifi_connectEndpoint_callback callback_connect;

//This call back will be invoked when client lost the connection to AP.
wifi_disconnectEndpoint_callback callback_disconnect;

wifi_telemetry_ops_t *callback_telemetry;

void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc)
{
    WIFI_LOG_INFO("Registering connect callback...\n");
    callback_connect=callback_proc;
}

void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc)
{
    WIFI_LOG_INFO("Registering disconnect callback...\n");
    callback_disconnect=callback_proc;
}

void wifi_telemetry_callback_register (wifi_telemetry_ops_t *telemetry_ops)
{
    WIFI_LOG_INFO("Registering telemetry callback...\n");
    callback_telemetry = telemetry_ops;
}

void telemetry_init(char* name)
{
    if (callback_telemetry) callback_telemetry->init(name);
}

void telemetry_event_s(char* marker, char* value)
{
    if (callback_telemetry) callback_telemetry->event_s(marker, value);
}

void telemetry_event_d(char* marker, int value)
{
    if (callback_telemetry) callback_telemetry->event_d(marker, value);
}

/****** Helper functions ******/
char* getValue(const char *buf, const char *keyword) {
    char *ptr     = NULL;
    char *saveptr = NULL;
 
    if(buf == NULL)
        return NULL;
    /* Goto the place where keyword is located in the string */
    ptr = strstr(buf, keyword);
    if (ptr == NULL) return NULL;

    strtok_r(ptr, "=", &saveptr);
    return (strtok_r(NULL, "\n", &saveptr));
}

char trimSpace(char *srcStr)
{
  char *tmpPtr1;
  char *tmpPtr2;
  for(tmpPtr2=tmpPtr1=srcStr;*tmpPtr1;tmpPtr1++)
  {
        if(!isspace(*tmpPtr1))
           *tmpPtr2++ = *tmpPtr1;
  }
  *tmpPtr2 = '\0';
  return 1;
}

int wpaCtrlSendCmd(char *cmd) {
    size_t return_len=sizeof(return_buf)-1;
    int ret;

    memset(return_buf, 0, return_len);
    if(NULL == g_wpa_ctrl) {
        WIFI_LOG_ERROR("Control interface is NULL. \n");
        return -1;
    }

    ret = wpa_ctrl_request(g_wpa_ctrl, cmd, strlen(cmd), return_buf, &return_len, NULL);

    if (ret == -2) {
        WIFI_LOG_INFO("cmd=%s timed out \n", cmd);
        return -2;
    } else if (ret < 0) {
        WIFI_LOG_INFO("cmd=%s failed \n", cmd);
        return -3;
    }
    return 0;
}

static int find_ssid_in_scan_results(const char* ssid)
{
    bool found = false;
    int i;
    if(NULL == ssid || ssid[0] == '\0')
    {
        WIFI_LOG_ERROR("SSID to find is null/empty");
        return found;
    }
    for (i = 0; i < ap_count; i++)
    {
        if (strncmp (ap_list[i].ap_SSID, ssid,MAX_SSID_LEN) == 0)
        {
            WIFI_LOG_INFO( "Found SSID match - bssid = %s rssi = %d ssid = %s\n",
                    ap_list[i].ap_BSSID, ap_list[i].ap_SignalStrength, ap_list[i].ap_SSID);
            found = true;
        }
        else
        {
            WIFI_LOG_TRACE("No SSID match - bssid = %s rssi = %d ssid = %s\n",
                    ap_list[i].ap_BSSID, ap_list[i].ap_SignalStrength, ap_list[i].ap_SSID);
        }
    }
    return found;
}

static BOOL wpa_supplicant_conf_reset()
{
    WIFI_LOG_INFO("Deleting conf file and making a new one\n");

    if (remove("/opt/secure/wifi/wpa_supplicant.conf") == 0)
    {
        WIFI_LOG_INFO("Removed File\n");
    }
    FILE *fp;
    fp = fopen("/opt/secure/wifi/wpa_supplicant.conf", "w");
    if (fp == NULL)
    {
        WIFI_LOG_INFO("Error in opening configuration file\n");
        return false;
    }
    fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
    fprintf(fp, "update_config=1\n");
    fclose(fp);
    return true;
}

static long timespec_diff_ms(struct timespec* ts1, struct timespec* ts2)
{
    return ((ts2->tv_sec - ts1->tv_sec)*1000L) + ((ts2->tv_nsec - ts1->tv_nsec)/1000000);
}

/******************************/

/*********Callback thread to send messages to Network Service Manager *********/
void* monitor_thread_task(void *param)
{
    char *start   = NULL;
    char *saveptr = NULL;

    char current_ssid[MAX_SSID_LEN+1] = {0}; // TODO: 32 chars won't be enough if undecoded SSID from wpa_supplicant has special chars (PACEXI5-2357)
    char current_bssid[ENET_LEN+1] = {0};    // fixed length 18 chars (aa:bb:cc:dd:ee:ff + '\0')

    char last_disconnected_bssid[ENET_LEN+1] = {0};
    int  last_disconnected_reason_code = 0;
    char last_disconnected_ssid[MAX_SSID_LEN+1] = {0};
    char out_of_range_ssid[MAX_SSID_LEN+1] = {0};

    char tmp_return_buf[8192];

    wifiStatusCode_t connError;
#ifdef WIFI_CLIENT_ROAMING
    pthread_mutex_init(&wifi_roam_lock,NULL);
    pthread_condattr_t attr;

    pthread_condattr_init( &attr);
    pthread_condattr_setclock( &attr, CLOCK_MONOTONIC);
    pthread_cond_init( &cond, &attr);
#endif

    while ((stop_monitor != true) && (g_wpa_monitor != NULL)) {
        if (wpa_ctrl_pending(g_wpa_monitor) > 0) {

            memset(event_buf, 0, sizeof(event_buf));
            event_buf_len = sizeof(event_buf) - 1;

            if (0 == wpa_ctrl_recv(g_wpa_monitor, event_buf, &event_buf_len)) {

                WIFI_LOG_DEBUG( "%s: wpa_ctrl_recv got event_buf = [%s]\n", __FUNCTION__, event_buf);

                start = strchr(event_buf, '>');
                if (start == NULL) continue;
                if ((strstr(start, WPA_EVENT_SCAN_STARTED) != NULL)&&(!bNoAutoScan)) {

                    // example event_buffer for WPA_EVENT_SCAN_STARTED:
                    // "<3>CTRL-EVENT-SCAN-STARTED "
                    // does not contain explicit information on the SSID for which "scan started"
                    // so get it from previously saved info (ssid_to_find), or by other means ("GET_NETWORK 0 ssid")

                    WIFI_LOG_INFO("Scan started \n");

                    if (!*ssid_to_find)
                    {
                        WIFI_LOG_INFO("ssid_to_find empty. Issuing 'GET_NETWORK 0 ssid' to get SSID being scanned for\n");
                        pthread_mutex_lock(&wpa_sup_lock);
                        wpaCtrlSendCmd("GET_NETWORK 0 ssid");
                        const char* ptr_start_quote = strchr (return_buf, '"'); // locate quote before SSID
                        char* ptr_end_quote = NULL; // reverse search to locate quote after SSID
                        if (ptr_start_quote && (ptr_end_quote = strrchr (ptr_start_quote, '"')) > ptr_start_quote)
                        {
                            *ptr_end_quote = '\0'; // replace quote after SSID with '\0'
                            strcpy (ssid_to_find, ptr_start_quote + 1);
                        }
                        pthread_mutex_unlock(&wpa_sup_lock);
                        WIFI_LOG_INFO("ssid based on network id = [%s] \n", return_buf);
                    }
                    WIFI_LOG_INFO("SSID to find = [%s] \n", ssid_to_find);
                    strcpy(scanned_ssid, ssid_to_find);

                    pthread_mutex_lock(&wpa_sup_lock);

                    /* Flush the BSS every time so that there is no stale information */
                    WIFI_LOG_INFO("Flushing the BSS now\n");
                    wpaCtrlSendCmd("BSS_FLUSH 0");

                    cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;
                    pthread_mutex_unlock(&wpa_sup_lock);
                }

                else if (strstr(start, WPA_EVENT_SCAN_RESULTS) != NULL) {
                    WIFI_LOG_INFO("Scan results received \n");
                    if (!bNoAutoScan)
                    {
                        if (*ssid_to_find)
                        {
                            pthread_mutex_lock(&wpa_sup_lock);
                            return_buf[0] = '\0';
                            wpaCtrlSendCmd("SCAN_RESULTS");
                            WIFI_LOG_INFO("Buffer Length = %lu \n",strlen(return_buf));
                            ap_count = parse_scan_results (return_buf, strlen (return_buf));
                            if (!find_ssid_in_scan_results (ssid_to_find))
                                WIFI_LOG_ERROR("SSID [%s] not found in scan results\n", ssid_to_find);
                            pthread_mutex_unlock(&wpa_sup_lock);
                        }
                        else
                        {
                            WIFI_LOG_ERROR("no SSID to find\n");
                        }
                    }
                    else
                    {
                        WIFI_LOG_INFO("Application is running wifi scan so skipping \n");
                    }
                    if (cur_scan_state == WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED) {
                        pthread_mutex_lock(&wpa_sup_lock);
                        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED;
                        pthread_mutex_unlock(&wpa_sup_lock);
                    }
                }

                else if((strstr(start, WPS_EVENT_AP_AVAILABLE_PBC) != NULL)) {
                    WIFI_LOG_INFO("WPS Connection in progress\n");
                    connError = WIFI_HAL_CONNECTING;
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, current_ssid, &connError);
                }

                else if(strstr(start, WPS_EVENT_TIMEOUT) != NULL) {
                    WIFI_LOG_INFO("WPS Connection timeout\n");
                    bIsWpsCompleted = TRUE;
                    connError = WIFI_HAL_ERROR_NOT_FOUND;
                    if (callback_disconnect) (*callback_disconnect)(1, "", &connError);
                }
                /* Adding WPS Overlap Detection Events , This happens when an enrollee detects two registrars with PBC session
   active.*/
                else if(strstr(start,WPS_EVENT_OVERLAP) !=  NULL) {
                     WIFI_LOG_ERROR("WPS Overlap detected. ! Canceling WPS Operation...\n");
                     bIsPBCOverlapDetected = TRUE;
                     // TODO - wpa_supplicant deafult behaviour is cancel wps operation so cancelling for now 
                     if(isDualBandSupported())                                          // For Xi6
                         stop_wifi_wps_connection();
                     else {                                                            // For Xi5
                         WIFI_LOG_ERROR("TELEMETRY_WPS_CONNECTION_STATUS:DISCONNECTED,WPS_PBC_OVERLAP \n");
                         connError = WIFI_HAL_ERROR_NOT_FOUND;
                         if (callback_disconnect) (*callback_disconnect)(1, "", &connError);
                     }
                     bIsWpsCompleted = TRUE;
                }

                else if(strstr(start, WPS_EVENT_SUCCESS) != NULL) {
                    bIsWpsCompleted = TRUE;
                    bNoAutoScan = FALSE;//Setting bNoAutoScan as FALSE since WPS is successful
                    WIFI_LOG_INFO("WPS is successful...Associating now\n");
                }

                else if(strstr(start, WPA_EVENT_CONNECTED) != NULL) {
                    WIFI_LOG_INFO("Authentication completed successfully and data connection enabled\n");

                    pthread_mutex_lock(&wpa_sup_lock);
                    /* Save the configuration */
                    if(isPrivateSSID){
                        wpaCtrlSendCmd("SAVE_CONFIG");
                        bUpdatedSSIDInfo=1;
                        WIFI_LOG_INFO("[%s:%d] Configuration Saved \n",__FUNCTION__,__LINE__);
                    }
 
                    int retStatus = wpaCtrlSendCmd("STATUS");
                    if (retStatus == -2)
                        telemetry_event_d("WIFIV_WARN_hal_timeout", 1);
                    int rc = snprintf (tmp_return_buf, sizeof(tmp_return_buf), "%s", return_buf);
                    if(rc < 0)
                        WIFI_LOG_ERROR("snprintf of tmp_return_buf failed\n");

                    const char* bssid_ptr = getValue(return_buf, "bssid");
                    const char *ptr;
                    if (bssid_ptr)
                    {
                        snprintf (current_bssid, sizeof(current_bssid), "%s", bssid_ptr);
                        ptr = bssid_ptr + strlen(bssid_ptr) + 1;
                    }
                    else
                    {
                        WIFI_LOG_ERROR( "BSSID is NULL. Status output = [%s]\n", tmp_return_buf);
                        current_bssid[0] = '\0';
                        ptr = return_buf;
                    }
                    const char *ssid_ptr = getValue(ptr, "ssid");
                    printf_decode ((u8*)current_ssid, sizeof(current_ssid), ssid_ptr ? ssid_ptr : "");
                    WIFI_LOG_INFO("Connected to BSSID [%s], SSID [%s]\n", current_bssid, current_ssid);
                    pthread_mutex_unlock(&wpa_sup_lock);

                    /* Clear the out of range SSID as there is an user intervention */
                    if(*out_of_range_ssid)
                    {
                        *out_of_range_ssid = 0;
                        WIFI_LOG_INFO("Out of range SSID : %s\n", out_of_range_ssid);
                    }

                    connError = WIFI_HAL_SUCCESS;

                    //pthread_mutex_lock(&wpa_sup_lock);
                    /* Save the BSSID in the configuration file */
//                    sprintf(cmd_buf, "SET_NETWORK 0 bssid %s",curr_bssid);
//                    wpaCtrlSendCmd(cmd_buf);

                    /* Do not store the PSK in the config file */
                    //wpaCtrlSendCmd("SET_NETWORK 0 mem_only_psk 1");

                    //pthread_mutex_unlock(&wpa_sup_lock);
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, current_ssid, &connError);
                }

                else if(strstr(start, WPA_EVENT_DISCONNECTED) != NULL) {

                    // example event_buffer for WPA_EVENT_DISCONNECTED:
                    // "<3>CTRL-EVENT-DISCONNECTED bssid=5c:b0:66:00:4d:10 reason=8"

                    char* name_value_entry = NULL;
                    strtok_r (start, " ", &saveptr); // skip past the "CTRL-EVENT-DISCONNECTED" in the event_buffer
                    while (NULL != (name_value_entry = strtok_r (NULL, " ", &saveptr)))
                    {
                        if (0 == strncmp (name_value_entry, "bssid=", strlen ("bssid=")))
                            snprintf (last_disconnected_bssid, sizeof(last_disconnected_bssid), "%s", name_value_entry + strlen ("bssid="));
                        else if (0 == strncmp (name_value_entry, "reason=", strlen ("reason=")))
                            last_disconnected_reason_code = atoi (name_value_entry + strlen ("reason="));
                    }

                    // Clear the out of range SSID on receiving the WPA_EVENT_DISCONNECTED event only if the
                    // disconnect is received from the router with reason code != PREVIOUS_AUTH_INVALID (i.e if reason_code!=2)
                    // and if there was a router reboot (i.e if out_of_range_ssid is populated)
                    if( *out_of_range_ssid && (last_disconnected_reason_code != PREVIOUS_AUTH_INVALID) )
                    {
                        *out_of_range_ssid = 0;
                        WIFI_LOG_INFO("Out of range SSID : %s\n", out_of_range_ssid);
                    }

                    // if current_bssid = last_disconnected_bssid, assume last_disconnected_ssid = current_ssid; else reset last_disconnected_ssid
                    snprintf (last_disconnected_ssid, sizeof(last_disconnected_ssid), "%s",
                            0 == strcasecmp (current_bssid, last_disconnected_bssid) ? current_ssid : "");

                    WIFI_LOG_INFO(
                            "Disconnected from BSSID [%s], reason_code [%d] (SSID [%s]), last successfully connected bssid [%s]\n",
                            last_disconnected_bssid, last_disconnected_reason_code, last_disconnected_ssid, current_bssid);

                    // set current BSSID and SSID to empty as we just disconnected
                    current_bssid[0] = '\0';
                    current_ssid[0] = '\0';

                    connError = WIFI_HAL_SUCCESS;
#ifdef WIFI_CLIENT_ROAMING
                    // Disable if any in progress Roaming
                    if( cur_roaming_state == WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_STARTED) { 
                        pthread_cond_signal(&cond);
                    }
                    postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime; // Connection state changed, Refresh backoff
                    backOffRefreshed = 1;
#endif
                    if (callback_disconnect) (*callback_disconnect)(1, last_disconnected_ssid, &connError);
                }

                else if (strstr (start, WPA_EVENT_TEMP_DISABLED) != NULL) {

                    // example event_buffer for WPA_EVENT_TEMP_DISABLED:
                    // "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="D375C1D9F8B041E2A1995B784064977B" auth_failures=1 duration=10 reason=AUTH_FAILED"
                    // holds an SSID encoded by wpa_supplicant's printf_encode function, so we need to printf_decode this

                    connError = WIFI_HAL_ERROR_CONNECTION_FAILED; // default value

                    char ssid[MAX_SSID_LEN+1] = "<UNKNOWN>";
                    int duration = -1;
                    int auth_failures = -1;
                    char reason[128] = "UNKNOWN";

                    const char* ptr_start_quote = strchr (start, '"'); // locate quote before SSID
                    char* ptr_end_quote = NULL; // reverse search to locate quote after SSID
                    if (ptr_start_quote && (ptr_end_quote = strrchr (ptr_start_quote, '"')) > ptr_start_quote)
                    {
                        *ptr_end_quote = '\0'; // replace quote after SSID with '\0' so printf_decode can work
                        printf_decode ((u8*)ssid, sizeof(ssid), ptr_start_quote + 1);
                        *ptr_end_quote = '"'; // put back the quote after SSID so search for other fields can work

                        // search for other fields after ssid field
                        char* name_value_entry = NULL;
                        strtok_r (ptr_end_quote, " ", &saveptr);
                        while (NULL != (name_value_entry = strtok_r (NULL, " ", &saveptr)))
                        {
                            if (0 == strncmp (name_value_entry, "auth_failures=", strlen ("auth_failures=")))
                                auth_failures = atoi (name_value_entry + strlen ("auth_failures="));
                            else if (0 == strncmp (name_value_entry, "duration=", strlen ("duration=")))
                                duration = atoi (name_value_entry + strlen ("duration="));
                            else if (0 == strncmp (name_value_entry, "reason=", strlen ("reason=")))
                                snprintf (reason, sizeof (reason), "%s", name_value_entry + strlen ("reason="));
                        }

                        if (0 == strcmp (reason, "WRONG_KEY")) {
                            connError = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
                        } else if (0 == strcmp (reason, "AUTH_FAILED"))
                            connError = WIFI_HAL_ERROR_AUTH_FAILED;
                    }

                    WIFI_LOG_INFO( "SSID [%s] disabled for %ds (auth_failures=%d), reason=%s, connError [%d]\n",
                            ssid, duration, auth_failures, reason, connError);

                    /* If the user enters the wrong credentials and connect_withSSID() API is called,
                     * then disconnect the device from the router */
                    /* If router is rebooted, then do not send the DISCONNECT command to the wpa supplicant
                     * and instead continue with the wpa_supplicant scan for SSID */
                    if(connError == WIFI_HAL_ERROR_INVALID_CREDENTIALS)
                    {
                        if(strlen(out_of_range_ssid) > 0)
                        {
                            /* In case of router reboot, do not send the notification to the application
                             * by calling the callback_connect() function and do not send DISCONNECT to wpa supplicant
                             * out_of_range_ssid holds the SSID of the router that was rebooted/out of range */
                            continue;
                        }
                        else
                        {
                            WIFI_LOG_INFO( "Connection failed due to invalid credential, Disconnecting...\n");
                            pthread_mutex_lock(&wpa_sup_lock);
                            wpaCtrlSendCmd("DISCONNECT");
                            pthread_mutex_unlock(&wpa_sup_lock);
                        }
                    }

                    if (callback_connect)
                      (*callback_connect) (1, ssid, &connError);
                }

                else if (strstr (start, WPA_EVENT_REENABLED) != NULL) {

                    // example event_buffer for WPA_EVENT_REENABLED:
                    // <3>CTRL-EVENT-SSID-REENABLED id=0 ssid="124ABCDEF!@#$%^&*()_+}{\\\":?><-"
                    // holds an SSID encoded by wpa_supplicant's printf_encode function, so we need to printf_decode this

                    char ssid[MAX_SSID_LEN+1] = "<UNKNOWN>";

                    const char* ptr_start_quote = strchr (start, '"'); // locate quote before SSID
                    char* ptr_end_quote = NULL; // reverse search to locate quote after SSID
                    if (ptr_start_quote && (ptr_end_quote = strrchr (ptr_start_quote, '"')) > ptr_start_quote)
                    {
                        *ptr_end_quote = '\0'; // replace quote after SSID with '\0' so printf_decode can work
                        printf_decode ((u8*)ssid, sizeof(ssid), ptr_start_quote + 1);
                        *ptr_end_quote = '"'; // put back the quote after SSID so search for other fields can work
                    }

                    WIFI_LOG_INFO( "SSID [%s] re-enabled\n", ssid);
                }

                else if((strstr(start, WPA_EVENT_NETWORK_NOT_FOUND) != NULL)&&(!bNoAutoScan)) {
                    // if WPA_EVENT_NETWORK_NOT_FOUND arrives, it means the network/SSID that was last scanned for was not found
                    // (btw, we would have already learnt this on receipt of WPA_EVENT_SCAN_RESULTS (in 'find_ssid_in_scan_results')
                    //  as events arrive in the order: WPA_EVENT_SCAN_STARTED, WPA_EVENT_SCAN_RESULTS, WPA_EVENT_NETWORK_NOT_FOUND)

                    // example event_buffer for WPA_EVENT_NETWORK_NOT_FOUND:
                    // "<3>CTRL-EVENT-NETWORK-NOT-FOUND "
                    // does not contain explicit information on the SSID that was "not found"
                    // but the SSID that was "not found" is the SSID that was last scanned for (for which we got the last WPA_EVENT_SCAN_STARTED)

                    WIFI_LOG_INFO("SSID [%s] not found in last scan\n", ssid_to_find);
                    connError = WIFI_HAL_ERROR_NOT_FOUND;

                    // if a WPS_CANCEL command is sent to wpa_supplicant when it is in a SCANNING state,
                    // it triggers a NETWORK_NOT_FOUND event; which we should ignore (or suffer XIONE-9407)
                    // TODO: revisit logic with wpa_supplicant v2.10+ (introduces WPS_EVENT_CANCEL on WPS_CANCEL)
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    if (timespec_diff_ms(&timespec_wps_cancel, &now) < 1000)
                    {
                        WIFI_LOG_WARN("Ignoring NETWORK_NOT_FOUND event received within 1s of WPS_CANCEL \n");
                        continue;
                    }

                    // extra logic to check if an SSID change is the cause of the "network not found"
                    // if currently disconnected (no current ssid) and last disconnect was from the SSID for which we just got a "not found"
                    if (!*current_ssid && *last_disconnected_ssid && (0 == strcmp (last_disconnected_ssid, ssid_to_find)))
                    {
                        // check if the BSS we were connected to was heard from in last scan
                        // if the BSS is still alive, its SSID must have changed as we just got a "not found" for its previous SSID
                        if (*last_disconnected_bssid)
                        {
                            pthread_mutex_lock(&wpa_sup_lock);
                            snprintf(cmd_buf, sizeof(cmd_buf), "BSS %s", last_disconnected_bssid);
                            wpaCtrlSendCmd(cmd_buf);
                            WIFI_LOG_TRACE("cmd_buf = [%s], return_buf = [%s]\n", cmd_buf, return_buf);
                            if (*return_buf) {
                                WIFI_LOG_INFO("BSSID [%s] had an SSID change\n", last_disconnected_bssid);
                                connError = WIFI_HAL_ERROR_SSID_CHANGED;
                            }
                            else {
                                WIFI_LOG_INFO("BSSID [%s] is down or not within range\n", last_disconnected_bssid);

                                /*  We enter this condition if the router is out of range/rebooted.
                                 *  If the router SSID is out of range, then set the out of range SSID */
                                strcpy(out_of_range_ssid, last_disconnected_ssid);
                                WIFI_LOG_INFO("Out of range SSID : %s\n", out_of_range_ssid);
                            }
                            pthread_mutex_unlock(&wpa_sup_lock);
                        }
                    }
                    if ((WIFI_HAL_ERROR_NOT_FOUND == connError) && (0 != strcmp (ssid_to_find, scanned_ssid)) && isPrivateSSID)
                    {
                        // Hidden SSIDs will be listed in scan results only if a scan probe request is being initiated from supplicant.
                        // Scan results is valid for 5s. In this gap, if a new connect request for hidden ssid comes,
                        // supplicant checks this new SSID in previoulsy scanned list and detect as AP not found.
                        // Here we are skipping this no ssid found error as a scan is not yet performed for the SSID to find.
                        WIFI_LOG_INFO("Skipping no ssid found error: Scanned SSID = [%s] SSID to find =  [%s]", scanned_ssid, ssid_to_find);
                        continue;
                    }
                    if (callback_disconnect) (*callback_disconnect)(1, ssid_to_find, &connError);
                } /* WPA_EVENT_NETWORK_NOT_FOUND */
#ifdef WIFI_CLIENT_ROAMING
               else if((strstr(start, WPA_EVENT_SIGNAL_CHANGE) != NULL) && isPrivateSSID) {
                   // RSSI Signal Threshold change detected for private SSID.
                   // Sample Event : <3>CTRL-EVENT-SIGNAL-CHANGE above=1 signal=-15 noise=-110 txrate=6000
                   //                <3>CTRL-EVENT-SIGNAL-CHANGE above=0 signal=-68 noise=-110 txrate=6000
                   // TODO :- Check if associated, Check state is connected
                   WIFI_LOG_DEBUG("RSSI Change event detected, Event = %s \n",start);
                   // Check If Roaming is enabled or not
                   if(pstRoamingCtrl.roamingEnable == true) {
                       int rssi=0,isAbove=0,readCount=0;
                       // Skip CTRL-EVENT-SIGNAL-CHANGE tags
                       char *eventData = strstr(start," ");
                       readCount = sscanf(eventData," above=%d signal=%d",&isAbove,&rssi);
                       if(readCount == 2) {
                           WIFI_LOG_DEBUG("Signal Change event received with RSSI=[%d] and isAbove=[%d] \n",rssi,isAbove);
                           if(isAbove == 0 && cur_roaming_state == WIFI_HAL_ROAM_STATE_ROAMING_IDLE) { // RSSI is below threshold , Trigger romaing timer
                               cur_roaming_state = WIFI_HAL_ROAM_STATE_SIGNAL_PROCESSING;
                               int time = 0;
                               if(cur_roaming_mode == WIFI_HAL_ROAMING_MODE_SELF_STEERING) 
                                   time = pstRoamingCtrl.postAssnSelfSteerTimeframe;
                               else if(cur_roaming_mode == WIFI_HAL_ROAMING_MODE_AP_STEERING)
                                   time = pstRoamingCtrl.postAssnAPctrlTimeframe;
                               pthread_create(&wifi_signal_mon_thread,NULL,start_wifi_signal_monitor_timer, (void*)time);
                            } else if(isAbove == 1 && cur_roaming_state == WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_STARTED){
                               WIFI_LOG_INFO("Signal strength is recovered, Stopping Roaming timer.\n");
                               postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime; // Roaming Disabled, Refresh backoff
                               backOffRefreshed = 1;
                               pthread_cond_signal(&cond); 
                            } else if(cur_roaming_state != WIFI_HAL_ROAM_STATE_ROAMING_IDLE){
                                WIFI_LOG_DEBUG("Roaming is in progres, Skipping signal change event \n");
                            }
                       } else {
                           WIFI_LOG_ERROR("Failed to parse signal change event. \n");
                       }
                   }
                   else {
                       WIFI_LOG_DEBUG("Skipping signal change event, Roaming is disabled.\n");
                   }
               }
               else if((strstr(start, RRM_EVENT_NEIGHBOR_REP_RXED) != NULL))
               {
                   WIFI_LOG_INFO("RRM Neighbor report received event\n");
                   if(pstRoamingCtrl.roamingEnable && pstRoamingCtrl.roam80211kvrEnable) {
                       cur_roaming_mode = WIFI_HAL_ROAMING_MODE_AP_STEERING; 
                       int ret = parse_neighbor_report_response(start,&stRrmNeighborRpt);
                       if(ret != RETURN_OK)
                           cur_rrm_nbr_rep_state = WIFI_HAL_RRM_NEIGHBOR_REP_STATE_INTERNAL_ERROR;
                       else 
                          cur_rrm_nbr_rep_state = WIFI_HAL_RRM_NEIGHBOR_REP_RECEIVED;
                   } else {
                       WIFI_LOG_DEBUG("RRM Skipping neighbor report, Roaming/KVR is disabled.\n");
                   }
              } else if ((strstr(start, RRM_EVENT_NEIGHBOR_REP_FAILED) != NULL)) {
                  WIFI_LOG_INFO("RRM Neighbor report failed event. \n");
                  cur_rrm_nbr_rep_state = WIFI_HAL_RRM_NEIGHBOR_REP_REQUEST_FAILED;
              }
              else if(strstr(start,WPA_EVENT_BEACON_LOSS) != NULL)
              {
                  WIFI_LOG_INFO("Beacon Loss event detected. Client may disconnect.\n");
                  telemetry_event_d("WIFIV_WARN_BcnLossdisconn", 1);
              } else if(strstr(start,"WNM-BTM-REQ-RECEIVED") != NULL)
              {
                  WIFI_LOG_INFO("WNM- BTM Request Received. \n");
              } else if(strstr(start,"WNM-BTM-RES-SENT") != NULL) {
                 WIFI_LOG_INFO("WNM- BTM Response Sent. \n");
                 cur_roaming_mode = WIFI_HAL_ROAMING_MODE_AP_STEERING;
              } else if(strstr(start, WPA_EVENT_AUTH_REJECT) != NULL ||
                        strstr(start, WPA_EVENT_ASSOC_REJECT) != NULL) {
                 /* Clear the out of range SSID as there is an user intervention */
                 if(*out_of_range_ssid)
                 {
                     *out_of_range_ssid = 0;
                     WIFI_LOG_INFO("Out of range SSID : %s\n", out_of_range_ssid);
                 }
              }
#endif  // WIFI_CLIENT_ROAMING
                else {
                    continue;
                }
            }
        }
        else {
            usleep(WPA_SUP_TIMEOUT);
        }
    } /* End while loop */
    return NULL;
} /* End monitor_thread function */


/**************************************************************************************************/
/*WIFI WPS Related Functions                                                                      */
/**************************************************************************************************/

INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool){
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue){
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong){ //Where does the PIN come from?
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin){
#if 0  
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID:%d\n", ssidIndex);
  uint32_t wps_pin = 0;
  if(NetAppWiFiGenerateWPSPin(hNetApp, &wps_pin) == NETAPP_SUCCESS){      //Trying to generate the pin and checking if the result is a success
    pin = wps_pin;
    return RETURN_OK;
  }
  WIFI_LOG_INFO("Error setting the device pin\n");
  return RETURN_ERR; 
#endif
return RETURN_OK;
}

INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods){
  
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //Return all the methods: Push and Pin
 
  if (!is_null_pointer(methods)){
    strcpy(methods, "Push and Pin");
    WIFI_LOG_INFO("Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string){
  
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //I think returning push and pin for this would be acceptable
  if (!is_null_pointer(output_string)){
    strcpy(output_string, "Push and Pull");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_setCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *methodString){
 
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  if (!is_null_pointer(methodString)){
    strcpy(methodString, "Push and Pin");
    WIFI_LOG_INFO("Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string){
 
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  return RETURN_OK;
}

INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *wps_pin){

    WIFI_LOG_INFO("WPS Pin Call\n");

    WIFI_LOG_DEBUG("wps_pin = %s\n", wps_pin);

    bool command_failed;

    if (wps_pin == NULL || *wps_pin == '\0') // NOTE: remove " || *wps_pin == '\0'" to allow PIN auto-generation
    {
        WIFI_LOG_ERROR("No PIN supplied.\n");
        return RETURN_ERR;
    }

    if (*wps_pin) // if PIN is supplied, validate it
    {
        pthread_mutex_lock(&wpa_sup_lock);
        sprintf(cmd_buf, "WPS_CHECK_PIN %s", wps_pin);
        // on success, return_buf contains supplied PIN.
        // on failure, return_buf contains "FAIL" if PIN is not 8 digits, "FAIL-CHECKSUM" otherwise (last digit != checksum of first 7 digits).
        command_failed = true;
        if (0 == wpaCtrlSendCmd(cmd_buf))
        {
            if (strncmp(return_buf, "FAIL", 4) == 0)
                WIFI_LOG_ERROR("command '%s' returned '%s'\n", cmd_buf, return_buf);
            else
                command_failed = false;
        }
        pthread_mutex_unlock(&wpa_sup_lock);
        if (command_failed)
            return RETURN_ERR;
    }

    pthread_mutex_lock(&wpa_sup_lock);
    if (cur_sup_state != WIFI_HAL_WPA_SUP_STATE_IDLE)
    {
        pthread_mutex_unlock(&wpa_sup_lock);
        WIFI_LOG_INFO("Connection is in progress, returning error \n");
        return RETURN_ERR;
    }

    isPrivateSSID = 1;
    wpaCtrlSendCmd("REMOVE_NETWORK 0");
    wpaCtrlSendCmd("SAVE_CONFIG");
    bUpdatedSSIDInfo = 1;

    //Trigger wps_pin
    bIsWpsCompleted = FALSE;
    sprintf(cmd_buf, "WPS_PIN any"); // the "any" is case-sensitive ("ANY" does not work)
    if (*wps_pin)
    {
        strcat(cmd_buf, " ");
        strcat(cmd_buf, wps_pin);
    }
    // on success, return_buf contains the PIN used for WPS negotiation with AP
    // on failure, return_buf starts with "FAIL..."
    command_failed = true;
    if (0 == wpaCtrlSendCmd(cmd_buf))
    {
        if (strncmp(return_buf, "FAIL", 4) == 0)
            WIFI_LOG_ERROR("command '%s' returned '%s'\n", cmd_buf, return_buf);
        else
        {
            command_failed = false;
            if (*wps_pin == '\0')
                strncat (wps_pin, return_buf, 8); // copy auto-generated PIN from return_buf into wps_pin
        }
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    if (command_failed)
        return RETURN_ERR;

    WIFI_LOG_INFO("Will be timing out if AP is not found after 120 seconds\n");

    if (false == wpa_supplicant_conf_reset())
        return RETURN_ERR;

    wifiStatusCode_t connError = WIFI_HAL_CONNECTING;
    (*callback_connect)(1, "", &connError);
    WIFI_LOG_INFO("Connection in progress..\n");

 #if 0
  INT* pinValue = 0;
  *pinValue = atoi(EnrolleePin);
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  if(NetAppWiFiConnectByPin(hNetApp, NETAPP_IFACE_WIRELESS, NULL, *pinValue, true) == NETAPP_SUCCESS){   //Connecting to the device using a pin and checking the result
    return RETURN_OK;
  }
  WIFI_LOG_INFO("Error connecting to device with enrollee pin... Check again\n");
  return RETURN_ERR;
#endif
    return RETURN_OK;
}

// Parse Scan results and fetch all WPS-PBC enabled accesspoints
int parse_wps_pbc_accesspoints(char *buf,wifi_wps_pbc_ap_t ap_list[])
{
    char *ptr     = NULL;
    char *saveptr = NULL;
    char ssid[MAX_SSID_LEN+1];
    char bssid[32];
    char rssi[8];
    char freq[8];
    int  apCount = 0;
    char *eptr = NULL;

    //Memset arrays
    memset(ssid,0,sizeof(ssid));
    memset(bssid,0,sizeof(bssid));
    memset(rssi,0,sizeof(rssi));
    memset(freq,0,sizeof(freq));

    /* skip heading */
    ptr = strstr(buf,"/ ssid");
    if (ptr == NULL) return -1;
    ptr += strlen("/ ssid") + 1;

    char* line = strtok_r(ptr, "\n", &saveptr);
    while(line != NULL && apCount < MAX_WPS_AP_COUNT)
    {
        if(strstr(line,"[WPS-PBC]") != NULL)
        {
            ssid[0] = '\0';
            bssid[0] = '\0';
            rssi[0] = '\0';
            freq[0] = '\0';
            sscanf(line,"%32s %5s %7s %*s %32s",bssid,freq,rssi,ssid);
            if((ssid[0] != '\0') && (bssid[0] != '\0') && (rssi[0] != '\0') && (freq[0] != '\0'))
            {
                WIFI_LOG_INFO("WPS-PBC AccessPoint[%d] : [SSID = %s , BSSID = %s , FREQ = %s , RSSI = %s ]\n",apCount,ssid,bssid,freq,rssi);
                strncpy(ap_list[apCount].ap_BSSID,bssid,sizeof(ap_list[apCount].ap_BSSID));
                strncpy(ap_list[apCount].ap_SSID,ssid,sizeof(ap_list[apCount].ap_SSID));
                ap_list[apCount].ap_Frequency = (int) strtol(freq,&eptr,10);
                ap_list[apCount].ap_FreqBand = (((ap_list[apCount].ap_Frequency/1000) == 5)?WIFI_HAL_FREQ_BAND_5GHZ:WIFI_HAL_FREQ_BAND_24GHZ);
                ap_list[apCount].ap_SignalStrength = (int) strtol(rssi,&eptr,10);
                apCount++;
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return apCount;
}

// Cancel WPS Pairing Operation
INT wifi_cancelWpsPairing ()
{
    int retStatus = RETURN_ERR;

    // Check for any inprogress WPS operation
    if(bIsWpsCompleted == FALSE)
    {
       stop_wifi_wps_connection();
       retStatus = RETURN_OK;
    }
    else
    {
        WIFI_LOG_INFO("No In-Progress WPS Operation, Skipping WPS_CANCEL. \n");
    }
    return retStatus;
}


// Cancel the WPS operation 
void stop_wifi_wps_connection()
{
    bNoAutoScan = FALSE;//Setting bNoAutoScan as FALSE since WPS fails
    if(bIsWpsCompleted == FALSE)
    {
        WIFI_LOG_INFO("Stopping  WPS operation.. \n");
        if (bWpsPBC && isDualBandSupported())
            pthread_cancel(wps_start_thread); // Lets forcefully stop the thread as we need to strictly maintain WPS time frame

        // Make sure that the mutex is not locked by wps thread & Cancel WPS operation
        if(pthread_mutex_trylock(&wpa_sup_lock) != 0)
        {
            pthread_mutex_unlock(&wpa_sup_lock);
            pthread_mutex_lock(&wpa_sup_lock);
        }
        clock_gettime(CLOCK_MONOTONIC, &timespec_wps_cancel);
        wpaCtrlSendCmd("WPS_CANCEL");
        // Abort scanning if any scanning is in progress
        if(cur_scan_state != WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE)
            wpaCtrlSendCmd("ABORT_SCAN");
        pthread_mutex_unlock(&wpa_sup_lock);

        // Inform netsrvmgr that WPS is failed and status is disconnected.
        wifiStatusCode_t connError;
        connError = WIFI_HAL_ERROR_NOT_FOUND; 
        if (callback_disconnect) (*callback_disconnect)(1, "", &connError);
        if(bIsPBCOverlapDetected == TRUE)
            WIFI_LOG_INFO("TELEMETRY_WPS_CONNECTION_STATUS:DISCONNECTED,WPS_PBC_OVERLAP\n");
        else
            WIFI_LOG_INFO("TELEMETRY_WPS_CONNECTION_STATUS:DISCONNECTED,WPS_TIME_OUT\n");
        bIsWpsCompleted = TRUE;
    }
}

// Check wether the station has dual band support
BOOL isDualBandSupported()
{
    FILE *fp = NULL;
    char cmd[BUFF_LEN_64];
    char result[BUFF_LEN_64];
    bool retStatus = false;

    memset(cmd,0,sizeof(cmd));
    memset(result,0,BUFF_LEN_64);

    snprintf(cmd,sizeof(cmd),"iw list | grep 'Band' | tr '\n' ' '");
    fp = popen(cmd,"r");
    if (fp != NULL)
    {
        if ((fgets(result, sizeof(result), fp) != NULL) && (result[0] != '\0'))
        {
            if((strstr(result,"Band 1:") != NULL) && (strstr(result,"Band 2:") != NULL))
            {
                // Dual Band since both Band 1 and Band 2 capabilties are present in iw list
                retStatus = true;
            }
            else
            {
                retStatus = false;
            }
        }
        pclose(fp);
    }
    else
    {
        WIFI_LOG_ERROR("isDualBandSupported() : popen() failed \n");
    }
    return retStatus;
}

// Initiate WPS connection to athe given BSSID
int triggerWpsPush(char *bssid)
{
    char cmd[32];
    int retStatus = -1;

    if(bssid != NULL)
    {
        memset(cmd,0,sizeof(cmd));
        snprintf(cmd,32,"WPS_PBC %s",bssid);
        WIFI_LOG_INFO("Initiating WPS connection to BSSID - %s \n",bssid );
        pthread_mutex_lock(&wpa_sup_lock);
        retStatus = wpaCtrlSendCmd(cmd);
        pthread_mutex_unlock(&wpa_sup_lock);
    }
    else
    {
        WIFI_LOG_ERROR("triggerWpsPush() failed , BSSID is NULL.! \n");
    }
    return retStatus;
}

// Start WPS operation with Band selection.
void* start_wifi_wps_connection(void *param)
{
    int apCount = 0;
    int i = 0;
    wifi_wps_pbc_ap_t ap_list[MAX_WPS_AP_COUNT];
    char tmpBuff[RETURN_BUF_LENGTH];
    int retry = 0;
    bIsWpsCompleted = FALSE;
    bIsPBCOverlapDetected = FALSE;

    // Continue scanning & try connecting Until WPS is successfull
    WIFI_LOG_INFO("Scanning for WPS-PBC access points on both 5 & 2.4 GHz Bands.\n");
    while(!bIsWpsCompleted) 
    {
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("BSS_FLUSH 0");
        bNoAutoScan = TRUE;
        wpaCtrlSendCmd("SCAN");

        // Check if scanning is failed due to in progress scanning
        if (strstr(return_buf, "FAIL-BUSY") != NULL) {
            WIFI_LOG_INFO("FAIL-BUSY due to in-progress scanning..  \n");
            wpaCtrlSendCmd("ABORT_SCAN");      
            wpaCtrlSendCmd("BSS_FLUSH 0");
            wpaCtrlSendCmd("SCAN");
        }

        pthread_mutex_unlock(&wpa_sup_lock);
        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;

        // Lets wait for scan results for max 6 seconds
        retry = 0;
        while ((cur_scan_state !=  WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) &&(retry++ < 1000)) {       
            usleep(6000);
        }

        // Get and Parse scan results and check for PBC enabled Accesspoints
        memset(tmpBuff,0,RETURN_BUF_LENGTH);
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("SCAN_RESULTS");
        strncpy(tmpBuff,return_buf,sizeof(tmpBuff));
        pthread_mutex_unlock(&wpa_sup_lock);
        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
        apCount = parse_wps_pbc_accesspoints(tmpBuff,ap_list);
        if(apCount != 0)
        {
            // Trying to get 5Ghz PBC enabled Accesspoints from scnaned list and start wps operation
            WIFI_LOG_INFO("Trying to establish WPS connection to 5GHz Accesspoint.\n");
            for(i=0; i<apCount; i++)
            {
                if(ap_list[i].ap_FreqBand == WIFI_HAL_FREQ_BAND_5GHZ)
                {
                    triggerWpsPush(ap_list[i].ap_BSSID);

                    // Initiated WPS operation let wait for results for max 5 seconds to connect
                    retry = 0;
                    while ((!bIsWpsCompleted) &&(retry++ < 1000)) {
                        usleep(5000);
                    }
                    if(!bIsWpsCompleted) 
                       WIFI_LOG_ERROR("Failed to connect to 5G AP - %s\n",ap_list[i].ap_SSID);
                    else {
                       // Adding Telemetry for Successful connection
                       WIFI_LOG_INFO("TELEMETRY_WPS_CONNECTION_STATUS:CONNECTED,%s,%s,5GHz,%d,%d \n",ap_list[i].ap_SSID,ap_list[i].ap_BSSID,ap_list[i].ap_SignalStrength,ap_list[i].ap_Frequency);
                       return NULL;
                    }
                }
            }

            // Looks like either we couldnt get a 5G AP or we couldnt connected to 5G AP. Lets try to connect to 2.4 G AP
            WIFI_LOG_INFO("Failed to get 5Ghz AP for WPS connection, Trying for 2.4GHz AP. \n");
            for(i=0; i<apCount; i++)
            {
                if(ap_list[i].ap_FreqBand == WIFI_HAL_FREQ_BAND_24GHZ)
                {
                    triggerWpsPush(ap_list[i].ap_BSSID);

                    // Initiated WPS operation let wait for results for max 5 seconds to connect
                    retry = 0;
                    while ((!bIsWpsCompleted) &&(retry++ < 1000)) {
                        usleep(5000);
                    }
                    if(!bIsWpsCompleted) // WPS connection is failed to 2.4GHz AP, 
                        WIFI_LOG_ERROR("Failed to connect to 2.4G AP - %s\n",ap_list[i].ap_SSID);
                    else {
                        // Adding Telemetry for Successful Connection
                        WIFI_LOG_INFO("TELEMETRY_WPS_CONNECTION_STATUS:CONNECTED,%s,%s,2.4GHz,%d,%d \n",ap_list[i].ap_SSID,ap_list[i].ap_BSSID,ap_list[i].ap_SignalStrength,ap_list[i].ap_Frequency);
                        return NULL;
                    }
                }
            }
        } // End Of if(apCount != 0)
        else
        {
            WIFI_LOG_INFO("Missing WPS_PBC AP in Scanned list, Continue Scanning...  \n");
        }
    } // End of while(!bIsWpsCompleted)
    return NULL;
}


INT wifi_setCliWpsButtonPush(INT ssidIndex){
 
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  
  WIFI_LOG_INFO("WPS Push Button Call\n");
  telemetry_event_d("WIFIV_ERR_WPS_button_pressed", 1);
  bWpsPBC = true;
  
  pthread_mutex_lock(&wpa_sup_lock);
  
  if (cur_sup_state != WIFI_HAL_WPA_SUP_STATE_IDLE) {
        pthread_mutex_unlock(&wpa_sup_lock);
        WIFI_LOG_INFO("Connection is in progress, returning error \n");
        return RETURN_ERR;
  }

  isPrivateSSID=1;
  wpaCtrlSendCmd("REMOVE_NETWORK 0");
  wpaCtrlSendCmd("SAVE_CONFIG");
  bUpdatedSSIDInfo=1;
  pthread_mutex_unlock(&wpa_sup_lock);
 
  if(isDualBandSupported())
 {
      WIFI_LOG_INFO("STB is Dual-Band supported. Initiating band seletion... \n");
      pthread_create(&wps_start_thread, NULL, start_wifi_wps_connection, NULL);
      // Start WPS timer
      signal(SIGALRM, stop_wifi_wps_connection);
      alarm(WPS_CON_TIMEOUT);
  }   
  else
  {
      WIFI_LOG_INFO("No Dual-Band support. Initiate Normal PBC.\n");
      bIsWpsCompleted = FALSE;
      pthread_mutex_lock(&wpa_sup_lock);
      wpaCtrlSendCmd("WPS_PBC");
      pthread_mutex_unlock(&wpa_sup_lock);
  }

  WIFI_LOG_INFO("Will be timing out if AP not found after 120 seconds\n");

  if (false == wpa_supplicant_conf_reset())
      return RETURN_ERR;

  wifiStatusCode_t connError;
  connError = WIFI_HAL_CONNECTING;
  (*callback_connect)(1, "", &connError);
  WIFI_LOG_INFO("Connection in progress..\n");

  WIFI_LOG_INFO("WIFI HAL: WPS Push sent successfully\n");
  return RETURN_OK;
}

INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int saveSSID,CHAR * eapIdentity,CHAR * carootcert,CHAR * clientcert,CHAR * privatekey){
  
  int retStatus = -1;
  WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  
  WIFI_LOG_INFO("Save SSID value:%d\n", saveSSID);

  pthread_mutex_lock(&wpa_sup_lock);          /* Locking in the mutex before connect */
  isPrivateSSID=saveSSID;
  if (isPrivateSSID) {
      WIFI_LOG_INFO("Will save network to wpa_supplicant.conf if connect is successful\n");
  }
  else { // LnF SSID
      WIFI_LOG_INFO("Will not save network to wpa_supplicant.conf\n");
  }


  WIFI_LOG_INFO("Requesting connection to AP\n");
  
  WIFI_LOG_INFO("Security mode:%d\n", AP_security_mode);
  retStatus=wpaCtrlSendCmd("REMOVE_NETWORK 0");
  if ((strstr (return_buf, "FAIL") != NULL) || (retStatus != 0))
  {
      WIFI_LOG_ERROR( "%s: REMOVE_NETWORK 0 failed error %d  \n", __FUNCTION__,retStatus);
  }
  
  wpaCtrlSendCmd("ADD_NETWORK");

  /* Set SSID */
  sprintf(cmd_buf, "SET_NETWORK 0 ssid \"%s\"", AP_SSID);
  wpaCtrlSendCmd(cmd_buf);

  if (AP_security_mode == WIFI_SECURITY_WPA_PSK_AES ||
      AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES ||
      AP_security_mode == WIFI_SECURITY_WPA_PSK_TKIP ||
      AP_security_mode == WIFI_SECURITY_WPA2_PSK_TKIP ||
      AP_security_mode == WIFI_SECURITY_WPA_WPA2_PSK ||
      AP_security_mode == WIFI_SECURITY_WPA3_PSK_AES ||
      AP_security_mode == WIFI_SECURITY_WPA3_SAE)
  {
      if(AP_security_mode == WIFI_SECURITY_WPA3_PSK_AES){
         WIFI_LOG_INFO("Security mode is WPA2/WPA3\n");
      }
      else if(AP_security_mode == WIFI_SECURITY_WPA3_SAE){
         WIFI_LOG_INFO("Security mode is WPA3\n");
      }
      else{
         WIFI_LOG_INFO("Security mode is PSK\n");
      }
      /* Key Management */
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt WPA-PSK SAE");
      wpaCtrlSendCmd(cmd_buf);

#ifdef RDKC
      /* Set the SAE Password */
      sprintf(cmd_buf, "SET_NETWORK 0 sae_password \"%s\"", AP_security_PreSharedKey);
      int status = wpaCtrlSendCmd(cmd_buf);
      if(strstr(return_buf, "FAIL") != NULL)
      {
         WIFI_LOG_ERROR("Failed to set sae_password\n");
      }
#endif

      /* Set the PSK */
      sprintf(cmd_buf, "SET_NETWORK 0 psk \"%s\"", AP_security_PreSharedKey);
      wpaCtrlSendCmd(cmd_buf);
      if(strstr(return_buf, "FAIL") != NULL){
        WIFI_LOG_INFO("Password may not be falling within spec\n");
        wifiStatusCode_t connError;
        connError = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
        if (callback_connect)
          (*callback_connect)(1, AP_SSID, &connError);
        else {
          WIFI_LOG_ERROR("erorr connecting to BSS (%d), but user didn't supply callback\n",
            connError);
        }
        pthread_mutex_unlock(&wpa_sup_lock);
        if (!isPrivateSSID)
        {
            isPrivateSSID = 1;
        }
        return RETURN_OK;
      }
  }
  else if (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP ||
           AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES ||
           AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP ||
           AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES ||
           AP_security_mode == WIFI_SECURITY_WPA_WPA2_ENTERPRISE)
  {
      WIFI_LOG_INFO("Security mode is WPA Enterprise\n");
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt WPA-EAP");
      wpaCtrlSendCmd(cmd_buf);
  }
  else if (AP_security_mode == WIFI_SECURITY_WEP_64 ||
           AP_security_mode == WIFI_SECURITY_WEP_128)
  {
      wpaCtrlSendCmd("SET_NETWORK 0 key_mgmt NONE");
      wpaCtrlSendCmd("SET_NETWORK 0 auth_alg OPEN SHARED");

      /*
       *Set the password as string or hex depends on the WEP key format.
       *If password length for WEP64/WEP128 is 5/13 then it must be ASCII key format
       */

      if (strlen(AP_security_PreSharedKey) == 5 || strlen(AP_security_PreSharedKey) ==13)
          sprintf(cmd_buf, "SET_NETWORK 0 wep_key0 \"%s\"", AP_security_PreSharedKey);
      else
          sprintf(cmd_buf, "SET_NETWORK 0 wep_key0 %s", AP_security_PreSharedKey);

      wpaCtrlSendCmd(cmd_buf);
  }
  else{
      WIFI_LOG_INFO("None\n");
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt NONE");
      wpaCtrlSendCmd(cmd_buf);
//      sprintf(cmd_buf, "SET_NETWORK 0 wep_key0 \"%s\"", AP_security_KeyPassphrase);
//      wpaCtrlSendCmd(cmd_buf);
  }
  
  /* Allow us to connect to hidden SSIDs */
  wpaCtrlSendCmd("SET_NETWORK 0 scan_ssid 1");
      
  if (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP ||
      AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES ||
      AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP ||
      AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES ||
      AP_security_mode == WIFI_SECURITY_WPA_WPA2_ENTERPRISE ||
      AP_security_mode == WIFI_SECURITY_WPA_PSK_AES ||
      AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES ||
      AP_security_mode == WIFI_SECURITY_WPA_WPA2_PSK)
  {
      WIFI_LOG_INFO("Setting TKIP values\n");
    
      wpaCtrlSendCmd("SET_NETWORK 0 pairwise CCMP TKIP");
          
      wpaCtrlSendCmd("SET_NETWORK 0 group CCMP TKIP");
          
      wpaCtrlSendCmd("SET_NETWORK 0 proto WPA RSN");
  }
  
  if (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP ||
      AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES ||
      AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP ||
      AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES ||
      AP_security_mode == WIFI_SECURITY_WPA_WPA2_ENTERPRISE)
  {
      WIFI_LOG_INFO("EAP Identity %s\n", eapIdentity);
      sprintf(cmd_buf, "SET_NETWORK 0 identity \"%s\"", eapIdentity);
      
      wpaCtrlSendCmd(cmd_buf);

      wpaCtrlSendCmd("SET_NETWORK 0 eap TLS");
  }
  
  WIFI_LOG_INFO("The carootcert:%s\n", carootcert);
  WIFI_LOG_INFO("The clientcert:%s\n", clientcert);
  WIFI_LOG_INFO("The privatekey:%s\n", privatekey);
  WIFI_LOG_DEBUG("The PSK key:%s\n", AP_security_PreSharedKey);
  WIFI_LOG_DEBUG("The KeyP key:%s\n", AP_security_KeyPassphrase);
  
  /* EAP with certificates */
  if (access(carootcert, F_OK) != -1){
      
      WIFI_LOG_INFO("CA Root certificate exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 ca_cert \"%s\"", carootcert);
      wpaCtrlSendCmd(cmd_buf);
  }

  if (access(clientcert, F_OK) != -1){
      
      WIFI_LOG_INFO("Client Certificate exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 client_cert \"%s\"", clientcert);
      wpaCtrlSendCmd(cmd_buf);
  }

  if (access(privatekey, F_OK) != -1){
      
      WIFI_LOG_INFO("Private Key exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 private_key \"%s\"", privatekey);
      wpaCtrlSendCmd(cmd_buf);
      
      sprintf(cmd_buf, "SET_NETWORK 0 private_key_passwd \"%s\"", AP_security_KeyPassphrase);
      WIFI_LOG_INFO("Command is:%s\n", cmd_buf);
      wpaCtrlSendCmd(cmd_buf);
  }
  
  wpaCtrlSendCmd("SET_NETWORK 0 mode 0");
  
  snprintf (ssid_to_find, sizeof (ssid_to_find), "%s", AP_SSID);
  WIFI_LOG_INFO("Setting ssid_to_find to [%s]\n", ssid_to_find);
  
  wpaCtrlSendCmd("ENABLE_NETWORK 0");
  wpaCtrlSendCmd("REASSOCIATE");
  
  if(saveSSID){
    WIFI_LOG_INFO("Connecting to the specified access point\n");
    wifiStatusCode_t connError;
    connError = WIFI_HAL_CONNECTING;
    if (callback_connect) (*callback_connect)(1, AP_SSID, &connError);    
  }    

  WIFI_LOG_INFO("Leaving WiFi Connect Endpoint function\n");
  pthread_mutex_unlock(&wpa_sup_lock);
  return RETURN_OK;
}

INT wifi_lastConnected_Endpoint(wifi_pairedSSIDInfo_t *pairedSSIDInfo){
    char buf[512];
    char *saveptr = NULL;
    static char ssid[32]={0};
    static char bssid[20]={0};
    static char security[64]={0};
    static char passphrase[64]={0};
    static char wep_key[128]={0};
    char *tokenKey;
    char *tokenValue;
    FILE *f = NULL;

    if(!bUpdatedSSIDInfo)
    {
        strcpy(pairedSSIDInfo->ap_ssid, ssid);
        strcpy(pairedSSIDInfo->ap_bssid, bssid);
        strcpy(pairedSSIDInfo->ap_security, security);
        strcpy(pairedSSIDInfo->ap_passphrase,passphrase);
        strcpy(pairedSSIDInfo->ap_wep_key,wep_key);
        return RETURN_OK;
    }
    f = fopen("/opt/secure/wifi/wpa_supplicant.conf", "r");
    if (NULL == f)
    {
        WIFI_LOG_ERROR("Failed to open wpa_supplicant.conf\n");
        return RETURN_ERR;
    }
    while (fgets(buf, sizeof(buf), f) != NULL)
    {
        tokenKey=strtok_r(buf,"\"=", &saveptr);
        if (tokenKey == NULL)
            continue;
        tokenValue=strtok_r(NULL,"\"=\n", &saveptr);
        trimSpace(tokenKey);
        if((tokenValue != NULL) && (strcasecmp(tokenKey,"ssid") == 0))
        {
            strcpy(pairedSSIDInfo->ap_ssid,tokenValue);
            strcpy(ssid,tokenValue);
            bUpdatedSSIDInfo=0;
        }
        else if((tokenValue != NULL) && (strcasecmp(tokenKey,"psk") == 0))
        {
            strcpy(pairedSSIDInfo->ap_passphrase,tokenValue);
            strcpy(passphrase,tokenValue);
        }
        else if((tokenValue != NULL) && (strcasecmp(tokenKey,"bssid") == 0))
        {
            strcpy(pairedSSIDInfo->ap_bssid,tokenValue);
            strcpy(bssid,tokenValue);
        }
        else if((tokenValue != NULL) && (strcasecmp(tokenKey,"key_mgmt") == 0))
        {
            trimSpace(tokenValue);
            strcpy(pairedSSIDInfo->ap_security,tokenValue);
            strcpy(security,tokenValue);
        }
        else if((tokenValue != NULL) && (strstr(tokenKey,"wep_key") != 0))
        {
           trimSpace(tokenValue);
           strcpy(pairedSSIDInfo->ap_wep_key,tokenValue);
           strcpy(wep_key,tokenValue);
           strcpy(pairedSSIDInfo->ap_passphrase,tokenValue);//Incase of WEP, wep_key is printed for passphrase
           strcpy(passphrase,tokenValue);
        }
    }
    fclose(f);

    if(pairedSSIDInfo->ap_ssid[0] == '\0') {
        WIFI_LOG_ERROR("No SSID in wpa_supplicant.conf\n");
        telemetry_event_d("WIFIV_ERR_NoSSIDconf", 1);
        return RETURN_ERR;
    }

    WIFI_LOG_DEBUG("%s: ap_ssid=[%s], ap_bssid=[%s]\n",
            __FUNCTION__, pairedSSIDInfo->ap_ssid, pairedSSIDInfo->ap_bssid);

    // BSSID will be empty if wpa_supplicant.conf does not have it
    // in this case, get BSSID from output of wpa control interface command "STATUS"
    // but use BSSID from "STATUS" only if SSID from "STATUS" = SSID from conf file (as any SSID not in conf file should be ignored)
    if (pairedSSIDInfo->ap_ssid[0] != '\0' && pairedSSIDInfo->ap_bssid[0] == '\0') // wpa_supplicant.conf file has SSID but not BSSID
    {
        pthread_mutex_lock(&wpa_sup_lock);
        int retStatus = wpaCtrlSendCmd("STATUS");
        if (retStatus == -2)
            telemetry_event_d("WIFIV_WARN_hal_timeout", 1);
        const char* current_bssid = getValue(return_buf, "bssid");
        WIFI_LOG_DEBUG("%s: current_bssid=[%s]\n", __FUNCTION__, current_bssid);
        if (current_bssid)
        {
            const char *ssid_ptr = getValue((char*) (strchr(current_bssid, '\0') + 1), "ssid"); // look for ssid after end of bssid
            WIFI_LOG_DEBUG("%s: ssid_ptr=[%s]\n", __FUNCTION__, ssid_ptr);
            if (ssid_ptr)
            {
                char current_ssid[MAX_SSID_LEN+1] = {0};
                printf_decode ((u8*)current_ssid, sizeof(current_ssid), ssid_ptr);
                WIFI_LOG_DEBUG("%s: current_ssid=[%s]\n", __FUNCTION__, current_ssid);
                if (strcmp(pairedSSIDInfo->ap_ssid, current_ssid) == 0)
                {
                    snprintf (pairedSSIDInfo->ap_bssid, sizeof(pairedSSIDInfo->ap_bssid), "%s", current_bssid);
                    snprintf (bssid, sizeof(bssid), "%s", current_bssid);
                    WIFI_LOG_DEBUG("%s: current_ssid matches ap_ssid. ap_bssid set to [%s]\n",
                            __FUNCTION__, pairedSSIDInfo->ap_bssid);
                }
            }
        }
        pthread_mutex_unlock(&wpa_sup_lock);
    }

    return RETURN_OK;
}

INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID){

 WIFI_LOG_INFO("SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
 
 WIFI_LOG_INFO("Received request to disconnect from AP\n");
 
 wpaCtrlSendCmd("DISCONNECT");
 
 return RETURN_OK;
}

// Clear SSID info from HAL
INT wifi_clearSSIDInfo(INT ssidIndex) {

    int status = RETURN_ERR;

    pthread_mutex_lock(&wpa_sup_lock);
    if (wpaCtrlSendCmd("REMOVE_NETWORK 0") == RETURN_OK) {
         if(wpaCtrlSendCmd("SAVE_CONFIG") == RETURN_OK) {
             WIFI_LOG_INFO("Cleared ssid info successfully. \n");
             status = RETURN_OK;
         } else {
             WIFI_LOG_ERROR("Error in saving configuration. \n ");
         }
    } else {
        WIFI_LOG_ERROR("Error in removing network. \n");
    } 
    pthread_mutex_unlock(&wpa_sup_lock);
    return status;
}


#ifdef WIFI_CLIENT_ROAMING

static int wifi_set_signal_monitor(int rssi_threshold)
{
    int status = RETURN_ERR;
    char cmd[BUFF_LEN_64];

    memset(cmd,0,sizeof(cmd));
    sprintf(cmd,"SIGNAL_MONITOR THRESHOLD=%d HYSTERESIS=2",rssi_threshold); // Adding HYSTERESIS to reduce events overhead. 
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("SIGNAL_MONITOR");
    status = wpaCtrlSendCmd(cmd);
    pthread_mutex_unlock(&wpa_sup_lock);
    if(status == RETURN_OK) {
        WIFI_LOG_INFO("Successfully started RSSI Signal monitor.\n ");
    } else {
        WIFI_LOG_ERROR("Failed to start RSSI Signal monitor. !\n ");
    }
    return status;
}

static int wifi_is_valid_threshold(int threshold)
{
    return ((threshold <= 0) && (threshold >= -200));
}

int wifi_setRoamingControl (int ssidIndex, wifi_roamingCtrl_t *pRoamingCtrlCfg)
{
    wifi_roamingCtrl_t currentCfg;
    int status = -1;
    char cmd[64];
    int refreshNeeded = 0;

    if(NULL == pRoamingCtrlCfg) {
        WIFI_LOG_ERROR("Input pointer is NULL \n");
        return -1;
    }
    memset(&currentCfg,0,sizeof(currentCfg));

    // Get Curret Configurations and set individual param only if changed
    status = wifi_getRoamingControl(ssidIndex,&currentCfg);
    if(status == 0) {
         if(currentCfg.roamingEnable != pRoamingCtrlCfg->roamingEnable) {
            snprintf(cmd_buf, sizeof(cmd_buf), "SET roaming_enable %d", pRoamingCtrlCfg->roamingEnable);
            pthread_mutex_lock(&wpa_sup_lock);
            status = wpaCtrlSendCmd(cmd_buf);
            pthread_mutex_unlock(&wpa_sup_lock);
            refreshNeeded = true;
            if(status != 0) {
                WIFI_LOG_ERROR("Failed to set roaming enable.! \n");
                return RETURN_ERR;
            }
            WIFI_LOG_INFO("Successfully set roamingEnable to %d\n", pRoamingCtrlCfg->roamingEnable);
         } else {
             WIFI_LOG_DEBUG("Trying to set same value for roamingEnable, Ignoring SET operation.\n");
         }
         pstRoamingCtrl.roamingEnable = pRoamingCtrlCfg->roamingEnable;

         // Check Roaming is enabled Or Not, If Not DONOT Allow to SET/GET
        /* if(pRoamingCtrlCfg->roamingEnable == 0 && currentCfg.roamingEnable == 0) {
             WIFI_LOG_ERROR("Romaing Feature is not enabled, Ignoring SET request.!\n");
             return -2;
          } */

         if(currentCfg.preassnBestThreshold != pRoamingCtrlCfg->preassnBestThreshold && wifi_is_valid_threshold(pRoamingCtrlCfg->preassnBestThreshold)) {
            snprintf(cmd_buf, sizeof(cmd_buf), "SET pre_assn_best_threshold_level %d", pRoamingCtrlCfg->preassnBestThreshold);
            pthread_mutex_lock(&wpa_sup_lock);
            status = wpaCtrlSendCmd(cmd_buf);
            pthread_mutex_unlock(&wpa_sup_lock);
            if(status != 0) {
                WIFI_LOG_ERROR("Failed to set pre_assn_best_threshold_level.! \n");
                return RETURN_ERR;
            }
            WIFI_LOG_INFO("Successfully set preassnBestThreshold to %d\n", pRoamingCtrlCfg->preassnBestThreshold);
         } else if(currentCfg.preassnBestThreshold == pRoamingCtrlCfg->preassnBestThreshold)
             WIFI_LOG_DEBUG("Trying to set same value for preassnBestThreshold, Ignoring SET operation.\n");
         else{
             WIFI_LOG_ERROR("Failed to set pre_assn_best_threshold_level - Invalid value = %d \n",pRoamingCtrlCfg->preassnBestThreshold);
             return RETURN_ERR;
         }
         pstRoamingCtrl.preassnBestThreshold = pRoamingCtrlCfg->preassnBestThreshold;

         if(currentCfg.preassnBestDelta != pRoamingCtrlCfg->preassnBestDelta) {
            snprintf(cmd_buf, sizeof(cmd_buf), "SET pre_assn_best_delta_level %d", pRoamingCtrlCfg->preassnBestDelta);
            pthread_mutex_lock(&wpa_sup_lock);
            status = wpaCtrlSendCmd(cmd_buf);
            pthread_mutex_unlock(&wpa_sup_lock);
            if(status != 0) {
                WIFI_LOG_ERROR("Failed to set pre_assn_best_delta_level.! \n");
                return RETURN_ERR;
            }
            WIFI_LOG_INFO("Successfully set preassnBestDelta to %d\n", pRoamingCtrlCfg->preassnBestDelta);
         } else {
             WIFI_LOG_DEBUG("Trying to set same value for preassnBestDelta, Ignoring SET operation.\n");
         }
         pstRoamingCtrl.preassnBestDelta = pRoamingCtrlCfg->preassnBestDelta;

        // Setting Post Association params
        if(currentCfg.roam80211kvrEnable != pRoamingCtrlCfg->roam80211kvrEnable) {
            snprintf(cmd_buf, sizeof(cmd_buf), "SET kvr_enable %d", pRoamingCtrlCfg->roam80211kvrEnable);
            pthread_mutex_lock(&wpa_sup_lock);
            wpaCtrlSendCmd(cmd_buf);
            pthread_mutex_unlock(&wpa_sup_lock);
            WIFI_LOG_INFO("Successfully set 80211kvrEnable to %d\n", pRoamingCtrlCfg->roam80211kvrEnable);
        } else {
            WIFI_LOG_DEBUG("Trying to set same value for 80211kvrEnable,Ignoring SET operation.\n");
        }
        pstRoamingCtrl.roam80211kvrEnable = pRoamingCtrlCfg->roam80211kvrEnable;

        // Save the current values to persistent file
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("SAVE_CONFIG");
        pthread_mutex_unlock(&wpa_sup_lock);
         
    } else {
        WIFI_LOG_ERROR("Failed to get current roaming Config \n");
    }
    // Setting Post Association params

    if(pstRoamingCtrl.selfSteerOverride != pRoamingCtrlCfg->selfSteerOverride) {
        pstRoamingCtrl.selfSteerOverride = pRoamingCtrlCfg->selfSteerOverride;
        refreshNeeded = true;
        WIFI_LOG_INFO("Successfully set selfSteerOverride to %d\n", pstRoamingCtrl.selfSteerOverride);
    } else {
        WIFI_LOG_DEBUG("Trying to set same value for selfSteerOverride, Ignoring SET operation.\n");
    }
    // Set Roaming Mode 
    if((pstRoamingCtrl.roam80211kvrEnable == true) && (pstRoamingCtrl.selfSteerOverride == false)) {
        cur_roaming_mode = WIFI_HAL_ROAMING_MODE_AP_STEERING;
        WIFI_LOG_INFO("Setting Roaming mode to AP Controlled..\n");
    }
    else {
        cur_roaming_mode = WIFI_HAL_ROAMING_MODE_SELF_STEERING;
        WIFI_LOG_INFO("Setting Roaming mode to Self Steering..\n");
    }

    if(pstRoamingCtrl.postAssnLevelDeltaConnected != pRoamingCtrlCfg->postAssnLevelDeltaConnected) {
        pstRoamingCtrl.postAssnLevelDeltaConnected = pRoamingCtrlCfg->postAssnLevelDeltaConnected;
        WIFI_LOG_INFO("Successfully set postAssnLevelDeltaConnected to %d\n", pstRoamingCtrl.postAssnLevelDeltaConnected);
    } else {
        WIFI_LOG_DEBUG("Trying to set same value for postAssnLevelDeltaConnected,Ignoring SET operation.\n");
    }

    if(pstRoamingCtrl.postAssnLevelDeltaDisconnected != pRoamingCtrlCfg->postAssnLevelDeltaDisconnected) {
        pstRoamingCtrl.postAssnLevelDeltaDisconnected = pRoamingCtrlCfg->postAssnLevelDeltaDisconnected;
        WIFI_LOG_INFO("Successfully set postAssnLevelDeltaDisconnected to %d\n", pstRoamingCtrl.postAssnLevelDeltaDisconnected);
    } else {
        WIFI_LOG_DEBUG("Trying to set same value for postAssnLevelDeltaDisconnected,Ignoring SET operation.\n");
    }

    if(pstRoamingCtrl.postAssnSelfSteerThreshold != pRoamingCtrlCfg->postAssnSelfSteerThreshold && wifi_is_valid_threshold(pRoamingCtrlCfg->postAssnSelfSteerThreshold)) {
        pstRoamingCtrl.postAssnSelfSteerThreshold = pRoamingCtrlCfg->postAssnSelfSteerThreshold;
        refreshNeeded = true;
        WIFI_LOG_INFO("Successfully set postAssnSelfSteerThreshold to %d\n",pstRoamingCtrl.postAssnSelfSteerThreshold);
    } else if(pstRoamingCtrl.postAssnSelfSteerThreshold == pRoamingCtrlCfg->postAssnSelfSteerThreshold) {
        WIFI_LOG_DEBUG("Trying to set same value for postAssnSelfSteerThreshold,Ignoring SET operation.\n");
    } else {
        WIFI_LOG_ERROR("Failed to set postAssnSelfSteerThreshold, Invalid Value = %d.\n",pRoamingCtrlCfg->postAssnSelfSteerThreshold);
    }

    if(pstRoamingCtrl.postAssnSelfSteerTimeframe != pRoamingCtrlCfg->postAssnSelfSteerTimeframe && pRoamingCtrlCfg->postAssnSelfSteerTimeframe >= 0) {
        pstRoamingCtrl.postAssnSelfSteerTimeframe = pRoamingCtrlCfg->postAssnSelfSteerTimeframe;
        postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime; // Timer changed, Refresh backoff
        backOffRefreshed = 1;
        WIFI_LOG_INFO("Successfully set postAssnSelfSteerTimeframe to %d\n", pstRoamingCtrl.postAssnSelfSteerTimeframe);
    } else if(pRoamingCtrlCfg->postAssnSelfSteerTimeframe < 0 ) {
         WIFI_LOG_ERROR("Failed to set postAssnSelfSteerTimeframe, Invalid Value = %d.\n",pRoamingCtrlCfg->postAssnSelfSteerTimeframe);
    }

    if(pstRoamingCtrl.postAssnBackOffTime != pRoamingCtrlCfg->postAssnBackOffTime) {
        pstRoamingCtrl.postAssnBackOffTime = pRoamingCtrlCfg->postAssnBackOffTime;
        postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime;
        backOffRefreshed = 1;
        WIFI_LOG_INFO("Successfully set postAssnBackOffTime to %d\n", pstRoamingCtrl.postAssnBackOffTime);
    } else {
        WIFI_LOG_DEBUG("Trying to set same value for postAssnBackOffTime,Ignoring SET operation.\n");
    }

    if(pstRoamingCtrl.postAssnAPctrlThreshold != pRoamingCtrlCfg->postAssnAPctrlThreshold && wifi_is_valid_threshold(pRoamingCtrlCfg->postAssnAPctrlThreshold)) {
        pstRoamingCtrl.postAssnAPctrlThreshold = pRoamingCtrlCfg->postAssnAPctrlThreshold;
        refreshNeeded = true;
        WIFI_LOG_INFO("Successfully set postAssnAPctrlThreshold to %d\n", pstRoamingCtrl.postAssnAPctrlThreshold);
    } else if(pstRoamingCtrl.postAssnAPctrlThreshold == pRoamingCtrlCfg->postAssnAPctrlThreshold) {
        WIFI_LOG_DEBUG("Trying to set same value for postAssnAPctrlThreshold,Ignoring SET operation.\n");
    } else {
        WIFI_LOG_ERROR("Failed to set postAssnAPctrlThreshold, Invalid Value = %d.\n",pRoamingCtrlCfg->postAssnAPctrlThreshold);
    }

    if(pstRoamingCtrl.postAssnAPctrlTimeframe != pRoamingCtrlCfg->postAssnAPctrlTimeframe && pRoamingCtrlCfg->postAssnAPctrlTimeframe >= 0) {
        pstRoamingCtrl.postAssnAPctrlTimeframe = pRoamingCtrlCfg->postAssnAPctrlTimeframe;
        postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime; // Timer changed, Refresh backoff
        backOffRefreshed = 1;
        WIFI_LOG_INFO("Successfully set postAssnAPctrlTimeframe to %d\n", pstRoamingCtrl.postAssnAPctrlTimeframe);
    } else if(pstRoamingCtrl.postAssnAPctrlTimeframe == pRoamingCtrlCfg->postAssnAPctrlTimeframe){
        WIFI_LOG_DEBUG("Trying to set same value for postAssnAPctrlTimeframe,Ignoring SET operation.\n");
    } else {
       WIFI_LOG_ERROR("Failed to set postAssnAPctrlTimeframe, Invalid Value = %d.\n",pRoamingCtrlCfg->postAssnAPctrlTimeframe);
    }

    // Refresh Signal monitor if  threshold or roaming mode is changed
    if((pstRoamingCtrl.roamingEnable == true) && (refreshNeeded == true)) {
       if(cur_roaming_mode == WIFI_HAL_ROAMING_MODE_SELF_STEERING ) {
            // Enable signal monitor if Roaming is enabled, Also reset BackOff
            wifi_set_signal_monitor(pstRoamingCtrl.postAssnSelfSteerThreshold);
        } else if(cur_roaming_mode == WIFI_HAL_ROAMING_MODE_AP_STEERING) {
            wifi_set_signal_monitor(pstRoamingCtrl.postAssnAPctrlThreshold);
        }
    } else if((pstRoamingCtrl.roamingEnable == false) &&  (refreshNeeded == true)) {
        // Disable Signal Monitor
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("SIGNAL_MONITOR");
        pthread_mutex_unlock(&wpa_sup_lock);
        // Disable if any in progress Roaming
        if( cur_roaming_state == WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_STARTED) {
            postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime; // Roaming Disabled, Refresh backoff
            backOffRefreshed = 1;
            pthread_cond_signal(&cond);
         }
    }

    // Save to persistent storage 
    status = persist_roaming_config(&pstRoamingCtrl);
    if(status != RETURN_OK) 
        WIFI_LOG_ERROR("Failed to save roaming Configuration.! \n");
    return status;
}   

int persist_roaming_config(wifi_roamingCtrl_t* pRoamingCtrl_data)
{
    cJSON *pRoamingCtrl_Json_Data = NULL;
    int retValue = 0;
    
    if (pRoamingCtrl_data != NULL) {
        pRoamingCtrl_Json_Data = cJSON_CreateObject();
        if(!pRoamingCtrl_Json_Data) {
            WIFI_LOG_ERROR("Failed to create JSON object \n");
            return RETURN_ERR;
        }

        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "roamingEnable", pRoamingCtrl_data->roamingEnable);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "preassnBestThreshold", pRoamingCtrl_data->preassnBestThreshold);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "preassnBestDelta", pRoamingCtrl_data->preassnBestDelta);

        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "selfSteerOverride", pRoamingCtrl_data->selfSteerOverride);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnLevelDeltaConnected", pRoamingCtrl_data->postAssnLevelDeltaConnected);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnLevelDeltaDisconnected", pRoamingCtrl_data->postAssnLevelDeltaDisconnected);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnSelfSteerThreshold", pRoamingCtrl_data->postAssnSelfSteerThreshold);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnSelfSteerTimeframe", pRoamingCtrl_data->postAssnSelfSteerTimeframe);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnBackOffTime", pRoamingCtrl_data->postAssnBackOffTime);

        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnAPctrlThreshold", pRoamingCtrl_data->postAssnAPctrlThreshold);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "postAssnAPctrlTimeframe", pRoamingCtrl_data->postAssnAPctrlTimeframe);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "80211kvrEnable", pRoamingCtrl_data->roam80211kvrEnable);

        if( writeToPersistentFile(WIFI_ROAMING_CONFIG_FILE , pRoamingCtrl_Json_Data) != 0)
            retValue = -1;
        cJSON_Delete(pRoamingCtrl_Json_Data);
    } else {
       retValue = -1;
       WIFI_LOG_ERROR("Input config is NULL, failed to save roaming config \n");
    }
    return retValue;
}
int wifi_getRoamingControl(INT ssidIndex, wifi_roamingCtrl_t *pRoamingCtrlCfg)
{
    char* ptr = NULL;
    int retStatus = RETURN_OK;

    WIFI_LOG_DEBUG("Entering ... (%s) \n",__FUNCTION__);

    if(pRoamingCtrlCfg == NULL) {
        WIFI_LOG_ERROR("Input Stats is NULL \n");
        return RETURN_ERR;
    }
    memcpy(pRoamingCtrlCfg,&pstRoamingCtrl,sizeof(wifi_roamingCtrl_t));
    // TODO :- Optimize Get Operation, Returning Global is Sufficient . ?
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("GET roaming_controls");
    if(retStatus == 0)
    {
        ptr = getValue(return_buf, "roaming_enable");
        if (ptr == NULL) {
            WIFI_LOG_ERROR("Failure in getting roaming_enable. \n");
            retStatus = RETURN_ERR;
            goto exit_err;
        }
        else {
            pRoamingCtrlCfg->roamingEnable = strtol(ptr,NULL,10);
            WIFI_LOG_DEBUG("[%s] Roaming Enable = %d\n",__FUNCTION__,pRoamingCtrlCfg->roamingEnable);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "pre_assn_best_threshold_level");
        if (ptr == NULL) {
            WIFI_LOG_ERROR("Failure in getting pre_assn_best_threshold_level. \n");
            retStatus = RETURN_ERR;
            goto exit_err;
        }
        else {
            pRoamingCtrlCfg->preassnBestThreshold = strtol(ptr,NULL,10);
            WIFI_LOG_DEBUG("[%s] preassnBestThreshold  = %d\n",__FUNCTION__,pRoamingCtrlCfg->preassnBestThreshold);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "pre_assn_best_delta_level");
        if (ptr == NULL) {
            WIFI_LOG_ERROR("Failure in getting pre_assn_best_delta_level. \n");
            retStatus = RETURN_ERR;
            goto exit_err;
        }
        else {
            pRoamingCtrlCfg->preassnBestDelta = strtol(ptr,NULL,10);
            WIFI_LOG_DEBUG("[%s] preassnBestDelta = %d\n",__FUNCTION__,pRoamingCtrlCfg->preassnBestDelta);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "kvr_enable");
        if (ptr == NULL) {
            // kvr_enable is not a mandatory param, in xi5 this param will not be available , hence don't return failure.
            WIFI_LOG_ERROR("Failure in getting kvr_enable. \n"); 
        } else {
            pRoamingCtrlCfg->roam80211kvrEnable = strtol(ptr,NULL,10);
            WIFI_LOG_DEBUG("[%s] roam80211kvrEnable = %d\n",__FUNCTION__,pRoamingCtrlCfg->roam80211kvrEnable);
        }

    } else {
        WIFI_LOG_ERROR("GET ROAMING_CONTROLS failed , Status = %d \n",retStatus);
        retStatus = RETURN_ERR;
    }
exit_err:
    pthread_mutex_unlock(&wpa_sup_lock);
    return retStatus;
}

char* readPersistentFile(char *fileName)
{
    FILE *fp = NULL;
    char *fileContent = NULL;
    if( 0 == access(fileName, F_OK) )
    {
        fp = fopen(fileName, "r");
        if (fp == NULL)
        {
            WIFI_LOG_ERROR("Failed to open persistent file. !\n ");
        }
        else
        {
            int ch_count = 0;
            fseek(fp, 0, SEEK_END);
            ch_count = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            fileContent = (char *) malloc(sizeof(char) * (ch_count + 1));
            if(fileContent == NULL) {
                WIFI_LOG_ERROR("Failed to allocate memory, readPersistentFile failed.\n ");
                fclose(fp);
                return fileContent;
            }
            fread(fileContent, 1, ch_count,fp);
            fileContent[ch_count] ='\0';
            fclose(fp);
        }
    }
    else
    {
        WIFI_LOG_ERROR("Missing persistent file!\n ");
    }
    return fileContent;
}
int writeToPersistentFile (char* fileName, cJSON* pRoaming_Data)
{
    FILE *fp = NULL;
    fp = fopen(fileName, "w");
    if (fp == NULL)
    {
        WIFI_LOG_ERROR("Failed to open persistent file. !\n ");
        return -1;
    }
    else
    {
        char* fileContent = cJSON_Print(pRoaming_Data);
        if(fileContent != NULL) {
            fprintf(fp, "%s", fileContent);
            free(fileContent);
            WIFI_LOG_DEBUG("Persistent file saved successfully.\n ");
        } else {
            WIFI_LOG_ERROR("Failed to format Json to string. !\n ");
        }
        fclose(fp);
    }
    return 0;
}
int initialize_roaming_config()
{
    char *pRoamingCtrl_data_file_content = NULL;
    int retValue = 0;
    int ssidIndex = 0;
    wifi_roamingCtrl_t pRoamingCtrl_data;
    cJSON *pRoamingCtrl_json = NULL;

    memset(&pRoamingCtrl_data,0,sizeof(wifi_roamingCtrl_t));
    memset(&pstRoamingCtrl,0,sizeof(wifi_roamingCtrl_t));

    // Initialize default values
    pRoamingCtrl_data.roamingEnable = WIFI_DEFAULT_ROAMING_ENABLE;
    pRoamingCtrl_data.preassnBestThreshold = WIFI_DEFAULT_PRE_ASSN_BEST_THRLD;
    pRoamingCtrl_data.preassnBestDelta = WIFI_DEFAULT_PRE_ASSN_BEST_DELTA;
    pRoamingCtrl_data.selfSteerOverride = WIFI_DEFAULT_SELF_STEER_OVERRIDE_ENABLE;
    pRoamingCtrl_data.postAssnLevelDeltaConnected = WIFI_DEFAULT_BEST_DELTA_CONNECTED;
    pRoamingCtrl_data.postAssnSelfSteerThreshold = WIFI_DEFAULT_POST_ASSN_SELF_STEER_THRESHOLD;
    pRoamingCtrl_data.postAssnSelfSteerTimeframe = WIFI_DEFAULT_POST_ASSN_SELF_STEER_TIMEFRAME;
    pRoamingCtrl_data.postAssnBackOffTime = WIFI_DEFAULT_POST_ASSN_BACKOFF_TIME;
    pRoamingCtrl_data.postAssnLevelDeltaDisconnected = WIFI_DEFAULT_BEST_DELTA_DISCONNECTED; 
    pRoamingCtrl_data.postAssnAPctrlThreshold = WIFI_DEFAULT_AP_CONTROL_THRESHOLD;
    pRoamingCtrl_data.postAssnAPctrlTimeframe = WIFI_DEFAULT_AP_CONTROL_TIMEFRAME;
    pRoamingCtrl_data.roam80211kvrEnable = false; 

    pRoamingCtrl_data_file_content = readPersistentFile(WIFI_ROAMING_CONFIG_FILE);
    // check if file is empty
    if(NULL == pRoamingCtrl_data_file_content) {
        WIFI_LOG_ERROR("Failed to read persistent file. !\n ");
    }
    if(pRoamingCtrl_data_file_content) {
        pRoamingCtrl_json = cJSON_Parse(pRoamingCtrl_data_file_content);
        free(pRoamingCtrl_data_file_content);
    }
     
    if(NULL == pRoamingCtrl_json) {
         WIFI_LOG_ERROR("Failed to parse configuration file !\n ");
    }
    else {
        
        if( !(cJSON_GetObjectItem(pRoamingCtrl_json,"roamingEnable")) || !(cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestThreshold") || !(cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestDelta")))) {
             WIFI_LOG_ERROR("Corrupted roaming values, Unable to load intial configs !\n ");
        } else {
            pRoamingCtrl_data.roamingEnable = cJSON_GetObjectItem(pRoamingCtrl_json,"roamingEnable")->valueint;
            pRoamingCtrl_data.preassnBestThreshold = cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestThreshold")->valueint;
            pRoamingCtrl_data.preassnBestDelta = cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestDelta")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"selfSteerOverride")) {
            pRoamingCtrl_data.selfSteerOverride = cJSON_GetObjectItem(pRoamingCtrl_json,"selfSteerOverride")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnLevelDeltaConnected")) {
            pRoamingCtrl_data.postAssnLevelDeltaConnected = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnLevelDeltaConnected")->valueint;
        } 
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnSelfSteerThreshold")) {
            pRoamingCtrl_data.postAssnSelfSteerThreshold = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnSelfSteerThreshold")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnSelfSteerTimeframe")) {
            pRoamingCtrl_data.postAssnSelfSteerTimeframe = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnSelfSteerTimeframe")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnBackOffTime")) {
            pRoamingCtrl_data.postAssnBackOffTime = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnBackOffTime")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnLevelDeltaDisconnected")) {
            pRoamingCtrl_data.postAssnLevelDeltaDisconnected = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnLevelDeltaDisconnected")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnAPctrlThreshold")) {
            pRoamingCtrl_data.postAssnAPctrlThreshold = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnAPctrlThreshold")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnAPctrlTimeframe")) {
            pRoamingCtrl_data.postAssnAPctrlTimeframe = cJSON_GetObjectItem(pRoamingCtrl_json,"postAssnAPctrlTimeframe")->valueint;
        }
        if(cJSON_GetObjectItem(pRoamingCtrl_json,"80211kvrEnable")) {
            pRoamingCtrl_data.roam80211kvrEnable = cJSON_GetObjectItem(pRoamingCtrl_json,"80211kvrEnable")->valueint;
        }
        cJSON_Delete(pRoamingCtrl_json);
    }

    // Setting Initial Values
    WIFI_LOG_INFO("Setting Initial Roaming Configuration :- [roamingEnable=%d,preassnBestThreshold=%d,preassnBestDelta=%d,selfSteerOverride=%d,postAssnLevelDeltaConnected=%d,postAssnSelfSteerThreshold=%d,postAssnSelfSteerTimeframe=%d,postAssnBackOffTime=%d,postAssnLevelDeltaDisconnected=%d,postAssnAPcontrolThresholdLevel=%d,postAssnAPcontrolTimeframe=%d,80211kvrEnable=%d]\n",pRoamingCtrl_data.roamingEnable,pRoamingCtrl_data.preassnBestThreshold,pRoamingCtrl_data.preassnBestDelta,pRoamingCtrl_data.selfSteerOverride,pRoamingCtrl_data.postAssnLevelDeltaConnected,pRoamingCtrl_data.postAssnSelfSteerThreshold,pRoamingCtrl_data.postAssnSelfSteerTimeframe,pRoamingCtrl_data.postAssnBackOffTime,pRoamingCtrl_data.postAssnLevelDeltaDisconnected,pRoamingCtrl_data.postAssnAPctrlThreshold,pRoamingCtrl_data.postAssnAPctrlTimeframe,pRoamingCtrl_data.roam80211kvrEnable);

    wifi_setRoamingControl(ssidIndex,&pRoamingCtrl_data); 
    return RETURN_OK;
}
#endif
int get_wifi_self_steer_matching_bss_list(const char* ssid_to_find,wifi_neighbor_ap_t neighborAPList[], int timeout)
{
    char tmpBuff[RETURN_BUF_LENGTH];
    int ap_count = 0;
    int retry = 0;
    int apCnt = 0,matchCount = 0;

    // initiate a scan and get the list of matching BSS
    WIFI_LOG_INFO( "Starting scan for best Neighbor SSIDs ... \n");
    bNoAutoScan = TRUE;
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("BSS_FLUSH 0");
    wpaCtrlSendCmd("SCAN");
    cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED; 
    pthread_mutex_unlock(&wpa_sup_lock);

    // Lets wait for the scan to complete
    while ((cur_scan_state !=  WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) &&(retry++ < 10)) {       
        usleep(timeout*100000);
    }
    // Get scan results
    memset(tmpBuff,0,sizeof(tmpBuff));
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("SCAN_RESULTS");
    strncpy(tmpBuff,return_buf,sizeof(tmpBuff));

    // Parse scan result, So that global ap_list will be updated with new scan results
    ap_count = parse_scan_results (tmpBuff, strlen (tmpBuff));
    for(apCnt = 0;apCnt<ap_count; apCnt++) {

        if ((strncmp (ap_list[apCnt].ap_SSID,ssid_to_find,MAX_SSID_LEN) == 0) && (matchCount<MAX_NEIGHBOR_LIMIT)) {
            WIFI_LOG_INFO("SCAN Results Matching BSS - ssid = [%s] bssid = [%s] rssi = [%d] freq = [%s]\n",
                    ap_list[apCnt].ap_SSID,ap_list[apCnt].ap_BSSID, ap_list[apCnt].ap_SignalStrength, ap_list[apCnt].ap_OperatingFrequencyBand);
            memcpy(&neighborAPList[matchCount],&ap_list[apCnt],sizeof(wifi_neighbor_ap_t));
            matchCount++;
        } else if(matchCount>=MAX_NEIGHBOR_LIMIT) {
            break;
        }
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return matchCount;
}
#ifdef WIFI_CLIENT_ROAMING
static int get_best_ap_from_neighbor_list(wifi_neighbor_ap_t neighborAPList[],int apCount,wifi_neighbor_ap_t* bestNeighbor)
{
    int count = 0;
    int retStatus = RETURN_ERR;
    wifi_neighbor_ap_t bestBss;

    if(apCount == 0) {
        WIFI_LOG_ERROR("BSS count is 0, Failed to get best AP from neighbor list.\n");
        return retStatus;
    }
    if(bestNeighbor == NULL) {
        WIFI_LOG_ERROR("Input neighbor struct is null, Failed to get best AP from neighbor list.\n");
        return retStatus;
    }
    memset(&bestBss,0,sizeof(wifi_neighbor_ap_t));
    for(count=0;count<apCount;count++) {
        if((bestBss.ap_SignalStrength == 0) || (bestBss.ap_SignalStrength < neighborAPList[count].ap_SignalStrength)) {  // 1st entry
            memcpy(&bestBss,&neighborAPList[count],sizeof(wifi_neighbor_ap_t));
         }
    }
    if(bestBss.ap_SSID[0] != '\0') {
        memcpy(bestNeighbor,&bestBss,sizeof(wifi_neighbor_ap_t));
        WIFI_LOG_INFO( "Selecting best  BSS [%s] with RSSI [%d] . \n",bestNeighbor->ap_BSSID,bestNeighbor->ap_SignalStrength);
    } else {
        WIFI_LOG_INFO( "Failed to get Best AP. !\n");
    }
    return RETURN_OK;
}
static int wifi_getRadioFrequencyFromChannel(int channel)
{

   if (channel==14)
        return 2484;
    else if (channel<14)
        return (channel*5)+2407;
    else if (channel>=182 && channel<=196)
        return (channel*5)+4000;
    else if (channel>=36 && channel<=165)
        return (channel*5)+5000;
    else
        return 0;
}

static void incrementBackoff(int *backOff)
{
    if(*backOff <= WIFI_MAX_POST_ASSN_BACKOFF_TIME) {
        *backOff = *backOff*2; // Increment only if it is less than Max backoff
    }
    return;
}
    

static int isWifiActivelyUsed()
{
    return 1; // TODO: Get the value dynamically
}
static int start_post_assoc_roaming(WIFI_HAL_ROAMING_MODE roamingMode)
{
    wifi_neighbor_ap_t neighborAPList[MAX_NEIGHBOR_LIMIT];
    int bssCount = 0;
    wifi_sta_stats_t currWifiStats;
    int radioIndex = 0;
    int retStatus = RETURN_ERR;

    memset(&neighborAPList,0,sizeof(neighborAPList));
    memset(&currWifiStats,0,sizeof(wifi_sta_stats_t));

    // Get the current stats params like ssid,bssid and rssi for current connection
    wifi_getStats(radioIndex, &currWifiStats);
    if(currWifiStats.sta_SSID[0] == '\0') {
        WIFI_LOG_ERROR("Failed to get current SSID, Skip Roaming. \n");
        return retStatus;
    }
    int timeout = 6;  //6 seconds timeout
    pthread_mutex_lock(&wifi_roam_lock);
    cur_roaming_state = WIFI_HAL_ROAM_STATE_AP_SELECTION;
    pthread_mutex_unlock(&wifi_roam_lock);
    bssCount = get_wifi_self_steer_matching_bss_list(currWifiStats.sta_SSID,neighborAPList,timeout);
    if(bssCount == 0) {
        WIFI_LOG_ERROR("No Matching BSS found to Roam. \n");
        incrementBackoff(&postAssocBackOffTime);
        return retStatus;
    }
    WIFI_LOG_INFO("Got %d matching  BSS for SSID %s \n",bssCount,currWifiStats.sta_SSID);

    int status;
    int rssiThreshold;
    int delta;
    wifi_neighbor_ap_t bestNeighbor;

    memset(&bestNeighbor,0,sizeof(wifi_neighbor_ap_t));
    if(roamingMode == WIFI_HAL_ROAMING_MODE_SELF_STEERING) {
        rssiThreshold = pstRoamingCtrl.postAssnSelfSteerThreshold;
    } else if (roamingMode == WIFI_HAL_ROAMING_MODE_AP_STEERING) {
        rssiThreshold = pstRoamingCtrl.postAssnAPctrlThreshold; 
    }
        
    status =  get_best_ap_from_neighbor_list(neighborAPList,bssCount,&bestNeighbor);
    // Check the validity of BSS
    if(status != RETURN_OK || (currWifiStats.sta_BSSID[0] == '\0') || (bestNeighbor.ap_BSSID[0] == '\0') ) {
        WIFI_LOG_ERROR("failed to get BSSID from Best BSS.\n");
        incrementBackoff(&postAssocBackOffTime);
        return retStatus;
    } else if(strncmp(currWifiStats.sta_BSSID,bestNeighbor.ap_BSSID,MAX_SSID_LEN-1) == 0) {
        WIFI_LOG_ERROR("Client is already connected to Best BSS, Skipping Roaming operation.\n");
        incrementBackoff(&postAssocBackOffTime); 
        return retStatus;
    }
    // Valid BSS and Not the one already connected, Set Delta based on Wifi Activity
    if(isWifiActivelyUsed() == true) {
        delta = pstRoamingCtrl.postAssnLevelDeltaConnected; //Delta level connected
    } else {
        delta = pstRoamingCtrl.postAssnLevelDeltaDisconnected; // delta level disconnected
    }
    if(currWifiStats.sta_RSSI < bestNeighbor.ap_SignalStrength && ((bestNeighbor.ap_SignalStrength-(int)currWifiStats.sta_RSSI) >= delta)) {
        WIFI_LOG_INFO("Selected [%s] as best AP for SSID [%s] with RSSI [%d]. \n",bestNeighbor.ap_BSSID,bestNeighbor.ap_SSID,bestNeighbor.ap_SignalStrength);
    } else {
        WIFI_LOG_ERROR("Skipping roam to %s based on RSSI delta,Current RSSI=[%d],Target RSSI=[%d],Delta=[%d] \n",bestNeighbor.ap_BSSID,(int)currWifiStats.sta_RSSI,bestNeighbor.ap_SignalStrength,delta);
        incrementBackoff(&postAssocBackOffTime); 
        return retStatus;
    }
    // Everything Looks good, Lets Roam to that BSSID
    char cmd[BUFF_LEN_64] = {0};
    sprintf(cmd,"ROAM %s",bestNeighbor.ap_BSSID);
    pthread_mutex_lock(&wpa_sup_lock);
    int roamStat = wpaCtrlSendCmd(cmd);
    pthread_mutex_unlock(&wpa_sup_lock);
    if(roamStat == RETURN_OK) {
        WIFI_LOG_INFO("WiFi ROAM: Roaming triggered to %s . \n",bestNeighbor.ap_BSSID);
        pthread_mutex_lock(&wifi_roam_lock);
        cur_roaming_state = WIFI_HAL_ROAM_STATE_ROAMING_TRIGGERED;
        pthread_mutex_unlock(&wifi_roam_lock);
        if(bestNeighbor.ap_SignalStrength >= pstRoamingCtrl.postAssnSelfSteerThreshold) {
            postAssocBackOffTime = pstRoamingCtrl.postAssnBackOffTime;  // Roaming is successfull and connected to a good AP Lets reset Back off timer.
            backOffRefreshed = 1; 
            WIFI_LOG_INFO("Successfully roamed to best AP.\n");
        } else {
            WIFI_LOG_INFO("Roaming is successful, But RSSI is still low. Increase Backoff\n");
            incrementBackoff(&postAssocBackOffTime);
        }
        retStatus = RETURN_OK;
    } else {
        WIFI_LOG_INFO("Failed to trigger ROAM operation. \n");
        incrementBackoff(&postAssocBackOffTime);
    }
    return retStatus;
}

/*
* @Brief: Start APP steer Roaming based on 802.11k neighbor reports
*
*/
int start_ap_steer_roaming()
{
    // Collect Neighbor Report, It will be already updated on wifi_rrm_neighbor_report_t stRrmNeighborRpt
    char freqList[BUFF_LEN_64];
    char cmd[BUFF_LEN_32];
    char freqStr[8];
    int apCount;
    int pos = 0;
    int status = 0;

   // Check if we have enough Neighbors
   memset(freqList,0,BUFF_LEN_64);
   memset(cmd,0,BUFF_LEN_32);

   // AP steer roaming, Update 802.11K neighbor report
   int isRRMSupported = wifi_get_rrm_support(); 
   if(isRRMSupported && (pstRoamingCtrl.roam80211kvrEnable == true)) {
       WIFI_LOG_INFO("RRM is enabled in current connection. trying to get Neighbor report. ! \n");
       wifi_rrm_neighbor_rep_request_t nbr_req;
       memset(&nbr_req,0,sizeof(wifi_rrm_neighbor_rep_request_t));
       memset(&stRrmNeighborRpt,0,sizeof(wifi_rrm_neighbor_report_t));
       cur_rrm_nbr_rep_state = WIFI_HAL_RRM_NEIGHBOR_REP_STATE_IDLE; 
       int status = wifi_getRRMNeighborReport(&nbr_req,&stRrmNeighborRpt);
       if(status == RETURN_OK) {
           WIFI_LOG_INFO("Successfully sent request for RRM Neighbors. \n");
       } else {
           WIFI_LOG_ERROR("Failure in getting RRM Neighbor report. \n");
       }
   } else {
       WIFI_LOG_INFO("RRM is not supported or Not enabled. \n");
   }

   if(stRrmNeighborRpt.neighbor_cnt > 0 && (pstRoamingCtrl.roam80211kvrEnable == true)) {
       for(apCount=0;apCount<stRrmNeighborRpt.neighbor_cnt;apCount++) {
           // Remove duplicate frequency before adding to list
           memset(&freqStr,0,sizeof(freqStr));
           snprintf(freqStr,sizeof(freqStr),"%d",stRrmNeighborRpt.neighbor_ap->freq);
           if(strstr(freqList,freqStr) == NULL) 
               pos += snprintf(&freqList[pos],BUFF_LEN_64," %s",freqStr);
       }
       WIFI_LOG_INFO("RRM, Setting scan Freq based on Neighbor report to - %s \n",freqList);
       snprintf(cmd,BUFF_LEN_32,"SET freq_list %s",freqList);
       pthread_mutex_lock(&wpa_sup_lock);
       wpaCtrlSendCmd(cmd);
       pthread_mutex_unlock(&wpa_sup_lock);
   } else {
       WIFI_LOG_INFO("802.11K Neighbor report not present, Scanning all channels for Roaming. \n");
   }
   start_post_assoc_roaming(WIFI_HAL_ROAMING_MODE_AP_STEERING); 

   // Disable Freq List
   pthread_mutex_lock(&wpa_sup_lock);
   wpaCtrlSendCmd("SET freq_list 0");
   pthread_mutex_unlock(&wpa_sup_lock);
}

void start_wifi_signal_monitor_timer(void *arg)
{
    int counter = 0;
    struct timespec to;
    struct timespec t;
    int rssiThreshold = 0;
    int timeIncrement = 0;
    static int prevTimeFrame = 0;
    int nextTimeFrame = 0;

    int timeFrame = (int*) arg;
    pthread_mutex_lock(&wifi_roam_lock);
    cur_roaming_state = WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_STARTED;
    pthread_mutex_unlock(&wifi_roam_lock);
    if(!backOffRefreshed) {

        // BackOff is not refreshed need to increment Time Frame
        if(postAssocBackOffTime > WIFI_MAX_POST_ASSN_BACKOFF_TIME) {
            nextTimeFrame = prevTimeFrame + postAssocBackOffTime/2;
        } else {
            nextTimeFrame = timeFrame + postAssocBackOffTime/2;
        }
        // Make sure that the next timeframe is within the limit.
        if(postAssocBackOffTime <= WIFI_MAX_POST_ASSN_BACKOFF_TIME && nextTimeFrame <= WIFI_MAX_POST_ASSN_TIME_FRAME) {
            timeFrame =  nextTimeFrame;
            prevTimeFrame = timeFrame;
        } else if(nextTimeFrame <= WIFI_MAX_POST_ASSN_TIME_FRAME) {
            timeFrame = prevTimeFrame + postAssocBackOffTime/2;
            prevTimeFrame = timeFrame;
        } else {
            timeFrame = prevTimeFrame;
        }
        timeIncrement = postAssocBackOffTime/2;

    } else {
        backOffRefreshed = 0;
        prevTimeFrame = timeFrame;
    }
    
    WIFI_LOG_INFO("Starting signal monitor thread, TimeFrame = %d with Backoff = %d.\n",timeFrame,timeIncrement);
    clock_gettime(CLOCK_MONOTONIC, &to);
    to.tv_sec += timeFrame;
    int retVal = -1;
    pthread_mutex_lock(&wifi_roam_lock);
    if((retVal = pthread_cond_timedwait(&cond,&wifi_roam_lock,&to)) == 0) {
        WIFI_LOG_INFO("Signal strength recovered or connection state changed, lets stop roaming timer. !\n");
        cur_roaming_state = WIFI_HAL_ROAM_STATE_ROAMING_IDLE;
        pthread_mutex_unlock(&wifi_roam_lock);
     }
     else if(retVal == ETIMEDOUT) {
         WIFI_LOG_INFO("Signal monitor timer expired, RSSI is still lower, trigger roaming operation.\n");
         cur_roaming_state = WIFI_HAL_ROAM_STATE_THRESHOLD_TIMER_EXPIRED;
         pthread_mutex_unlock(&wifi_roam_lock);
         if(cur_roaming_mode == WIFI_HAL_ROAMING_MODE_SELF_STEERING) {
             WIFI_LOG_INFO("Starting Self steer roaming... \n");
             start_post_assoc_roaming(WIFI_HAL_ROAMING_MODE_SELF_STEERING);
             rssiThreshold = pstRoamingCtrl.postAssnSelfSteerThreshold;
         } else if(cur_roaming_mode == WIFI_HAL_ROAMING_MODE_AP_STEERING){
             WIFI_LOG_INFO("Starting AP-Controlled roaming... \n");
             start_ap_steer_roaming();
             rssiThreshold = pstRoamingCtrl.postAssnAPctrlThreshold;
         } else {
             WIFI_LOG_ERROR("Unrecognized roaming mode, skipping Roaming operation.\n");
         }
         //  Refresh signal_monitor
         wifi_set_signal_monitor(rssiThreshold);
     } else {
         WIFI_LOG_ERROR("Wifi Roam conditional wait failed.! \n");
         pthread_mutex_unlock(&wifi_roam_lock);
     }
     pthread_mutex_lock(&wifi_roam_lock);
     cur_roaming_state = WIFI_HAL_ROAM_STATE_ROAMING_IDLE;
     pthread_mutex_unlock(&wifi_roam_lock);
}

int wifi_get_rrm_support() 
{
    int retStatus = 0;
    int rrmSupport = 0;

    // Get RRM Support using wpa_cli command
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("GET_RRM_SUPPORT");
    if(retStatus == RETURN_OK && return_buf[0] != '\0' ) {
        rrmSupport = strtol(return_buf,NULL,10);
    } else {
        WIFI_LOG_ERROR("Failed to get RRM support.\n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return rrmSupport;
}

/**
 * @brief This API Gets the 802.11K Neighbor report from the Associated Accesspoint by sending Neighbor request.
 *
 * @param[in]  nbr_req -  Neighbor report request structure 
 * @param[out] nbr_rpt - Neighbor report structure
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_getRRMNeighborReport(wifi_rrm_neighbor_rep_request_t* nbr_req, wifi_rrm_neighbor_report_t* nbr_rpt)
{
    int retStatus = RETURN_ERR;
    int retry;
    char bssid[32];
    int ssidIndex=1;
     
    // Check if the client is Associated by checking the current bssid.
    memset(bssid,0,sizeof(bssid));
    if(wifi_getBaseBSSID(ssidIndex, bssid) == RETURN_ERR || bssid[0] == '\0') {
        WIFI_LOG_ERROR("Client is not associated, RRM request failed.\n");
        return retStatus;
    }

    retStatus = wifi_sendNeighborReportRequest(nbr_req);
    if(retStatus == 0) {
       retry = 0;
       // Wait Max of 1 seconds for getting RRM event
       while (((cur_rrm_nbr_rep_state != WIFI_HAL_RRM_NEIGHBOR_REP_RECEIVED)) &&(retry++ < 10)) { 
            usleep(100000);
       }
       if(retry >= 10) {
           WIFI_LOG_ERROR("Failed to get RRM response, Request timed out.!\n");
       } else if(cur_rrm_nbr_rep_state == WIFI_HAL_RRM_NEIGHBOR_REP_REQUEST_FAILED) {
           WIFI_LOG_ERROR("RRM neighbor report request failed.\n");
       } else if (cur_rrm_nbr_rep_state == WIFI_HAL_RRM_NEIGHBOR_REP_STATE_INTERNAL_ERROR) {
           WIFI_LOG_ERROR("RRM neighbor report report received, But failed to parse.\n");
       } else if (cur_rrm_nbr_rep_state == WIFI_HAL_RRM_NEIGHBOR_REP_RECEIVED) {
           WIFI_LOG_INFO("RRM Neighbor report succesfully received.\n");
           //memcpy(nbr_rpt,&stRrmNeighborRpt,sizeof(wifi_rrm_neighbor_report_t));
           retStatus = RETURN_OK;
       }
    } else {
        WIFI_LOG_ERROR("Failed to send RRM Neighbor Request. \n");
    }
    cur_rrm_nbr_rep_state = WIFI_HAL_RRM_NEIGHBOR_REP_STATE_IDLE;
    return retStatus;
}

/**
 * @brief This API sends the 802.11K Neighbor report request to the Associated Accesspoint.
 *
 * @param[in]  nbr_req -  Neighbor report request structure 
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_sendNeighborReportRequest(wifi_rrm_neighbor_rep_request_t* nbr_req)
{
    char cmd[BUFF_LEN_64];
    int retStatus = RETURN_ERR;

    memset(cmd,0,BUFF_LEN_64);

    if(nbr_req->ssid[0] != '\0') {
        WIFI_LOG_DEBUG("Sending RRM neighbor request with ssid=%s, lci=%d, civic=%d \n",nbr_req->ssid,nbr_req->lci,nbr_req->civic);
        snprintf(cmd,sizeof(cmd),"NEIGHBOR_REP_REQUEST ssid=\"%s\" lci=%d civic=%d",nbr_req->ssid,nbr_req->lci,nbr_req->civic);
    } else {
        snprintf(cmd,sizeof(cmd),"NEIGHBOR_REP_REQUEST");
    }
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd(cmd);
    pthread_mutex_unlock(&wpa_sup_lock);
    if(retStatus == 0) {
        WIFI_LOG_INFO("RRM Neighbor report request sent successfully \n");
        retStatus = RETURN_OK;
    } else {
        WIFI_LOG_ERROR("Failed to send RRM Request, cmd = %s \n",cmd);
    }
    return retStatus;
}

/**
 * @brief This API sends the 802.11K Neighbor report request to the Associated Accesspoint.
 *
 * @param[in] nbr_response - Neighbor response buffer from wpa_supplicant event buffer
 * @param[in]  nbr_rpt -  Neighbor report  structure 
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
int parse_neighbor_report_response(char *nbr_response,wifi_rrm_neighbor_report_t *nbr_rpt)
{

    char bssid[BUFF_LEN_32];
    char info[BUFF_LEN_32];
    int op_class,channel,phy_type;

    if(!nbr_response || nbr_response[0] == '\0') {
        WIFI_LOG_ERROR("Unable to parse - Neighbor response is NULL. \n");
        return RETURN_ERR;
    } else if(!nbr_rpt) {
        WIFI_LOG_ERROR("Unable to parse - Input Neighbor report is NULL \n");
        return RETURN_ERR;
    }

    // Sample Response Pattern
    //<3>RRM-NEIGHBOR-REP-RECEIVED bssid=ec:aa:a0:81:7f:20 info=0x1801 op_class=0 chan=153 phy_type=1 lci=0100080010000000000000000000000000000000000406000000000000060101 civic=02000b0000ed000000
    if(sscanf(nbr_response,"%*s bssid=%s info=%s op_class=%d chan=%d phy_type=%d",bssid,info,&op_class,&channel,&phy_type) == 5) {
        int i;
        int match = 0;
        // Check if the bssid is already present in list
        for(i=0;i<nbr_rpt->neighbor_cnt;i++) {
            if(strncmp(nbr_rpt->neighbor_ap[i].bssid,bssid,MAX_SSID_LEN) == 0) {
                match = 1;
                break;
             }  
        }
        if(!match && (nbr_rpt->neighbor_cnt < MAX_NEIGHBOR_LIMIT)) {
            strncpy(nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].bssid,bssid,sizeof(nbr_rpt->neighbor_ap->bssid));
            strncpy(nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].bssidInfo,info,sizeof(nbr_rpt->neighbor_ap->bssidInfo));
            nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].channel = channel;
            nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].op_class = op_class;
            nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].phy_type = phy_type;
            nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].freq = wifi_getRadioFrequencyFromChannel(channel);
            WIFI_LOG_INFO("RRM Neighbor[%d] -  Bssid = %s , Info = %s, op_class=%d, Channel = %d, Phy_Type = %d, Freq=%d\n ",nbr_rpt->neighbor_cnt,nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].bssid,nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].bssidInfo,nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].op_class,nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].channel,nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].phy_type,nbr_rpt->neighbor_ap[nbr_rpt->neighbor_cnt].freq);
             nbr_rpt->neighbor_cnt+=1;
      } else if(match){
          WIFI_LOG_INFO("BSSID already present in neighbor list, Skipping %s \n",bssid);
      } else {
          WIFI_LOG_INFO("Maximum neighbors added to list, Skipping.\n");
      }
   } else {
         WIFI_LOG_INFO("Failed to Parse Neighbor Report - Skipping entry\n");
   }
   return RETURN_OK;
}
#endif // WIFI_CLIENT_ROAMING

WiFiHalStatus_t getwifiStatusCode()
{
    return WIFISTATUS_HAL_COMPLETED;
}

void wifi_printf(const char *level, const char *format, ...)
{
  va_list arg_list;

  struct timeval now;
  gettimeofday(&now, NULL);
  printf("[%6s] %9ld.%06ld - ", level, now.tv_sec, now.tv_usec);

  va_start(arg_list, format);
  vprintf(format, arg_list);
  va_end(arg_list);
}
