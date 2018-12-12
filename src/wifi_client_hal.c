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
#include "rdk_debug.h"
#include <signal.h>
#include <wifi_client_hal.h>
#include <unistd.h>

#ifdef WIFI_CLIENT_ROAMING
#include "cJSON.h"
#endif
//This call back will be invoked when client automatically connect to AP.

wifi_connectEndpoint_callback callback_connect;

//This call back will be invoked when client lost the connection to AP.
wifi_disconnectEndpoint_callback callback_disconnect;

#include <wpa_ctrl.h>

#include <stdint.h>
typedef uint8_t u8;
// added to be able to use wpa_supplicant's 'printf_decode' utility function to decode the SSIDs encoded by wpa_supplicant
extern size_t printf_decode(u8 *buf, size_t maxlen, const char *str);

#define LOG_NMGR "LOG.RDK.WIFIHAL"
#define WPA_SUP_TIMEOUT     500000       /* 500 msec */
#define MAX_SSID_LEN        32           /* Maximum SSID name */
#define MAX_PASSWORD_LEN    64           /* Maximum password length */
#define ENET_LEN            17           /* Length of bytes for displaying an Ethernet address, e.g., 00:00:00:00:00:00.*/
#define CSPEC_LEN           20           /* Channel Spec string length */
#define RETURN_BUF_LENGTH   8192         /* Return buffer length */
#define BUFF_LEN_32         MAX_SSID_LEN /* Buffer Length 32 */
#define BUFF_LEN_64         64           /* Buffer Length 64*/
#define MAX_WPS_AP_COUNT    5            /* Max number of PBC enabled Access Points */
#define WPS_CON_TIMEOUT     120          /* WPS connection timeout */

#ifdef WIFI_CLIENT_ROAMING
#define WIFI_ROAMING_CONFIG_FILE "/opt/wifi/wifi_roamingControl.json"  /* Persistent storage for Roaming Configuration */
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

typedef enum {
    WIFI_HAL_FREQ_BAN_NONE,
    WIFI_HAL_FREQ_BAND_24GHZ,
    WIFI_HAL_FREQ_BAND_5GHZ,
} WIFI_HAL_FREQ_BAND;

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
BOOL bIsWpsCompleted = FALSE;
BOOL bIsPBCOverlapDetected = FALSE;

/* Initialize the state of the supplicant */
WIFI_HAL_WPA_SUP_STATE cur_sup_state = WIFI_HAL_WPA_SUP_STATE_IDLE;
WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state_from_supp = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
extern WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state;

char event_buf[4096];                   /* Buffer to store the event results */
bool stop_monitor;
static int isPrivateSSID=1;                  /* Variable to check whether to save to conf file - Default value is 1 (Will save to conf file) */
size_t event_buf_len;
pthread_t wps_start_thread;


// Parse WPS-PBC enabled access points from Scan results
int parse_wps_pbc_accesspoints(char *buf,wifi_wps_pbc_ap_t ap_list[]);
// Start WPS operation with Band selection
void start_wifi_wps_connection(void *param);
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
int persist_roaming_config(wifi_roamingCtrl_t*);
#endif

char ssid_to_find[MAX_SSID_LEN+1] = {0};

/****** Helper functions ******/
char* getValue(char *buf, char *keyword) {
    char *ptr = NULL;
 
    if(buf == NULL)
        return NULL;
    /* Goto the place where keyword is located in the string */
    ptr = strstr(buf, keyword);
    if (ptr == NULL) return NULL;

    strtok(ptr, "=");
    return (strtok(NULL, "\n"));
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
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Control interface is NULL. \n");
        return -1;
    }

    ret = wpa_ctrl_request(g_wpa_ctrl, cmd, strlen(cmd), return_buf, &return_len, NULL);

    if (ret == -2) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: cmd=%s timed out \n", cmd);
        return -2;
    } else if (ret < 0) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: cmd=%s failed \n", cmd);
        return -1;
    }
    return 0;
}

static int find_ssid_in_scan_results(const char* ssid)
{
    bool found = false;
    int i;
    for (i = 0; i < ap_count; i++)
    {
        if (strcmp (ap_list[i].ap_SSID, ssid) == 0)
        {
            RDK_LOG (RDK_LOG_INFO, LOG_NMGR, "WIFI_HAL: Found SSID match - bssid = %s rssi = %d ssid = %s\n",
                    ap_list[i].ap_BSSID, ap_list[i].ap_SignalStrength, ap_list[i].ap_SSID);
            found = true;
        }
        else
        {
            RDK_LOG (RDK_LOG_TRACE1, LOG_NMGR, "WIFI_HAL: No SSID match - bssid = %s rssi = %d ssid = %s\n",
                    ap_list[i].ap_BSSID, ap_list[i].ap_SignalStrength, ap_list[i].ap_SSID);
        }
    }
    return found;
}

/******************************/

/*********Callback thread to send messages to Network Service Manager *********/
void monitor_thread_task(void *param)
{
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Inside monitor thread task \n");
    char *start;

    char current_ssid[MAX_SSID_LEN+1] = {0}; // TODO: 32 chars won't be enough if undecoded SSID from wpa_supplicant has special chars (PACEXI5-2357)
    char current_bssid[ENET_LEN+1] = {0};    // fixed length 18 chars (aa:bb:cc:dd:ee:ff + '\0')

    char last_disconnected_bssid[ENET_LEN+1] = {0};
    int  last_disconnected_reason_code = 0;
    char last_disconnected_ssid[MAX_SSID_LEN+1] = {0};

    char tmp_return_buf[8192];

    wifiStatusCode_t connError;

    while ((stop_monitor != true) && (g_wpa_monitor != NULL)) {
        if (wpa_ctrl_pending(g_wpa_monitor) > 0) {

            memset(event_buf, 0, sizeof(event_buf));
            event_buf_len = sizeof(event_buf) - 1;

            if (0 == wpa_ctrl_recv(g_wpa_monitor, event_buf, &event_buf_len)) {

                RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR, "%s: wpa_ctrl_recv got event_buf = [%s]\n", __FUNCTION__, event_buf);

                start = strchr(event_buf, '>');
                if (start == NULL) continue;
                if ((strstr(start, WPA_EVENT_SCAN_STARTED) != NULL)&&(!bNoAutoScan)) {

                    // example event_buffer for WPA_EVENT_SCAN_STARTED:
                    // "<3>CTRL-EVENT-SCAN-STARTED "
                    // does not contain explicit information on the SSID for which "scan started"
                    // so get it from previously saved info (ssid_to_find), or by other means ("GET_NETWORK 0 ssid")

                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan started \n");

                    if (!*ssid_to_find)
                    {
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: ssid_to_find empty. Issuing 'GET_NETWORK 0 ssid' to get SSID being scanned for\n");
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
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: ssid based on network id = [%s] \n", return_buf);
                    }
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID to find = [%s] \n", ssid_to_find);

                    pthread_mutex_lock(&wpa_sup_lock);

                    /* Flush the BSS every time so that there is no stale information */
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Flushing the BSS now\n");
                    wpaCtrlSendCmd("BSS_FLUSH 0");

                    cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;
                    pthread_mutex_unlock(&wpa_sup_lock);
                }

                else if (strstr(start, WPA_EVENT_SCAN_RESULTS) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan results received \n");
                    if (!bNoAutoScan)
                    {
                        if (*ssid_to_find)
                        {
                            pthread_mutex_lock(&wpa_sup_lock);
                            return_buf[0] = '\0';
                            wpaCtrlSendCmd("SCAN_RESULTS");
                            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Buffer Length = %d \n",strlen(return_buf));
                            ap_count = parse_scan_results (return_buf, strlen (return_buf));
                            if (!find_ssid_in_scan_results (ssid_to_find))
                                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: SSID [%s] not found in scan results\n", ssid_to_find);
                            pthread_mutex_unlock(&wpa_sup_lock);
                        }
                        else
                        {
                            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: no SSID to find\n");
                        }
                    }
                    else
                    {
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Application is running wifi scan so skipping \n");
                    }
                    if (cur_scan_state == WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED) {
                        pthread_mutex_lock(&wpa_sup_lock);
                        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED;
                        pthread_mutex_unlock(&wpa_sup_lock);
                    }
                }

                else if((strstr(start, WPS_EVENT_AP_AVAILABLE_PBC) != NULL)) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS Connection in progress\n");
                    connError = WIFI_HAL_CONNECTING;
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, current_ssid, &connError);
                }

                else if(strstr(start, WPS_EVENT_TIMEOUT) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS Connection timeout\n");
                    connError = WIFI_HAL_ERROR_NOT_FOUND;
                    if (callback_disconnect) (*callback_disconnect)(1, "", &connError);
                }
                /* Adding WPS Overlap Detection Events , This happens when an enrollee detects two registrars with PBC session
   active.*/
                else if(strstr(start,WPS_EVENT_OVERLAP) !=  NULL) {
                     RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: WPS Overlap detected. ! Canceling WPS Operation...\n");
                     bIsPBCOverlapDetected = TRUE;
                     // TODO - wpa_supplicant deafult behaviour is cancel wps operation so cancelling for now 
                     if(isDualBandSupported())                                          // For Xi6
                         stop_wifi_wps_connection();
                     else {                                                            // For Xi5
                         RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"TELEMETRY_WPS_CONNECTION_STATUS:DISCONNECTED,WPS_PBC_OVERLAP");
                         connError = WIFI_HAL_ERROR_NOT_FOUND;
                         if (callback_disconnect) (*callback_disconnect)(1, "", &connError);
                     }
                }

                else if(strstr(start, WPS_EVENT_SUCCESS) != NULL) {
                    bIsWpsCompleted = TRUE;
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS is successful...Associating now\n");
                }

                else if(strstr(start, WPA_EVENT_CONNECTED) != NULL) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Authentication completed successfully and data connection enabled\n");

                    pthread_mutex_lock(&wpa_sup_lock);
                    /* Save the configuration */
                    if(isPrivateSSID){
                        wpaCtrlSendCmd("SAVE_CONFIG");
                        bUpdatedSSIDInfo=1;
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"[%s:%d] WIFI_HAL: Configuration Saved \n",__FUNCTION__,__LINE__);
                    }
                    wpaCtrlSendCmd("STATUS");
                    snprintf (tmp_return_buf, sizeof(tmp_return_buf), "%s", return_buf);
                    const char* bssid_ptr = getValue(return_buf, "bssid");
                    char *ptr;
                    if (bssid_ptr)
                    {
                        snprintf (current_bssid, sizeof(current_bssid), "%s", bssid_ptr);
                        ptr = bssid_ptr + strlen(bssid_ptr) + 1;
                    }
                    else
                    {
                        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR, "BSSID is NULL. Status output = [%s]\n", tmp_return_buf);
                        current_bssid[0] = '\0';
                        ptr = return_buf;
                    }
                    const char *ssid_ptr = getValue(ptr, "ssid");
                    printf_decode (current_ssid, sizeof(current_ssid), ssid_ptr ? ssid_ptr : "");
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connected to BSSID [%s], SSID [%s]\n", current_bssid, current_ssid);
                    pthread_mutex_unlock(&wpa_sup_lock);

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
                    strtok (start, " "); // skip past the "CTRL-EVENT-DISCONNECTED" in the event_buffer
                    while (NULL != (name_value_entry = strtok (NULL, " ")))
                    {
                        if (0 == strncmp (name_value_entry, "bssid=", strlen ("bssid=")))
                            snprintf (last_disconnected_bssid, sizeof(last_disconnected_bssid), "%s", name_value_entry + strlen ("bssid="));
                        else if (0 == strncmp (name_value_entry, "reason=", strlen ("reason=")))
                            last_disconnected_reason_code = atoi (name_value_entry + strlen ("reason="));
                    }

                    // if current_bssid = last_disconnected_bssid, assume last_disconnected_ssid = current_ssid; else reset last_disconnected_ssid
                    snprintf (last_disconnected_ssid, sizeof(last_disconnected_ssid), "%s",
                            0 == strcasecmp (current_bssid, last_disconnected_bssid) ? current_ssid : "");

                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,
                            "WIFI_HAL: Disconnected from BSSID [%s], reason_code [%d] (SSID [%s]), last successfully connected bssid [%s]\n",
                            last_disconnected_bssid, last_disconnected_reason_code, last_disconnected_ssid, current_bssid);

                    // set current BSSID and SSID to empty as we just disconnected
                    current_bssid[0] = '\0';
                    current_ssid[0] = '\0';

                    connError = WIFI_HAL_SUCCESS;

                    // variable just to hold "last_disconnected_ssid" in double quotes as this is what was passed into disconnect callback earlier
                    // TODO: clean this up; check if not double quoting will cause issues
                    char last_disconnected_ssid_with_quotes[MAX_SSID_LEN+2+1] = {0};
                    snprintf (last_disconnected_ssid_with_quotes, sizeof(last_disconnected_ssid_with_quotes), "\"%s\"", last_disconnected_ssid);
                    if (callback_disconnect) (*callback_disconnect)(1, last_disconnected_ssid_with_quotes, &connError);
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
                        printf_decode (ssid, sizeof(ssid), ptr_start_quote + 1);
                        *ptr_end_quote = '"'; // put back the quote after SSID so search for other fields can work

                        // search for other fields after ssid field
                        char* name_value_entry = NULL;
                        strtok (ptr_end_quote, " ");
                        while (NULL != (name_value_entry = strtok (NULL, " ")))
                        {
                            if (0 == strncmp (name_value_entry, "auth_failures=", strlen ("auth_failures=")))
                                auth_failures = atoi (name_value_entry + strlen ("auth_failures="));
                            else if (0 == strncmp (name_value_entry, "duration=", strlen ("duration=")))
                                duration = atoi (name_value_entry + strlen ("duration="));
                            else if (0 == strncmp (name_value_entry, "reason=", strlen ("reason=")))
                                snprintf (reason, sizeof (reason), "%s", name_value_entry + strlen ("reason="));
                        }

                        if (0 == strcmp (reason, "WRONG_KEY"))
                            connError = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
                        else if (0 == strcmp (reason, "AUTH_FAILED"))
                            connError = WIFI_HAL_ERROR_AUTH_FAILED;
                    }

                    RDK_LOG (RDK_LOG_INFO, LOG_NMGR, "WIFI_HAL: SSID [%s] disabled for %ds (auth_failures=%d), reason=%s, connError [%d]\n",
                            ssid, duration, auth_failures, reason, connError);

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
                        printf_decode (ssid, sizeof(ssid), ptr_start_quote + 1);
                        *ptr_end_quote = '"'; // put back the quote after SSID so search for other fields can work
                    }

                    RDK_LOG (RDK_LOG_INFO, LOG_NMGR, "WIFI_HAL: SSID [%s] re-enabled\n", ssid);
                }

                else if((strstr(start, WPA_EVENT_NETWORK_NOT_FOUND) != NULL)&&(!bNoAutoScan)) {
                    // if WPA_EVENT_NETWORK_NOT_FOUND arrives, it means the network/SSID that was last scanned for was not found
                    // (btw, we would have already learnt this on receipt of WPA_EVENT_SCAN_RESULTS (in 'find_ssid_in_scan_results')
                    //  as events arrive in the order: WPA_EVENT_SCAN_STARTED, WPA_EVENT_SCAN_RESULTS, WPA_EVENT_NETWORK_NOT_FOUND)

                    // example event_buffer for WPA_EVENT_NETWORK_NOT_FOUND:
                    // "<3>CTRL-EVENT-NETWORK-NOT-FOUND "
                    // does not contain explicit information on the SSID that was "not found"
                    // but the SSID that was "not found" is the SSID that was last scanned for (for which we got the last WPA_EVENT_SCAN_STARTED)

                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID [%s] not found in last scan\n", ssid_to_find);
                    connError = WIFI_HAL_ERROR_NOT_FOUND;

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
                            RDK_LOG( RDK_LOG_TRACE1, LOG_NMGR,"WIFI_HAL: cmd_buf = [%s], return_buf = [%s]\n", cmd_buf, return_buf);
                            if (*return_buf) {
                                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: BSSID [%s] had an SSID change\n", last_disconnected_bssid);
                                connError = WIFI_HAL_ERROR_SSID_CHANGED;
                            }
                            else {
                                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: BSSID [%s] is down or not within range\n", last_disconnected_bssid);
                            }
                            pthread_mutex_unlock(&wpa_sup_lock);
                        }
                    }

                    // variable just to hold "ssid_to_find" in double quotes as this is what was passed into disconnect callback earlier
                    // TODO: clean this up; check if not double quoting will cause issues
                    char ssid_to_find_with_quotes[MAX_SSID_LEN+2+1] = {0};
                    snprintf (ssid_to_find_with_quotes, sizeof(ssid_to_find_with_quotes), "\"%s\"", ssid_to_find);
                    if (callback_disconnect) (*callback_disconnect)(1, ssid_to_find_with_quotes, &connError);
                } /* WPA_EVENT_NETWORK_NOT_FOUND */

                else {
                    continue;
                }
            }
        }
        else {
            usleep(WPA_SUP_TIMEOUT);
        }
    } /* End while loop */
} /* End monitor_thread function */


void wifi_getStats(INT radioIndex, wifi_sta_stats_t *stats)
{
    char *ptr;
    char *bssid, *ssid;
    int phyrate, noise, rssi,freq;
    int retStatus = -1;

    if(NULL == stats)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Input Stats is NULL \n");
        return;
    }
        
    /* Find the currently connected BSSID and run signal_poll command to get the stats */
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("STATUS");
    if(retStatus == 0)
    {
        bssid = getValue(return_buf, "bssid");
        if (bssid == NULL) 
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: BSSID is NULL in Status output\n");
            goto exit;
        }
        else
            strcpy(stats->sta_BSSID, bssid);
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"bssid=%s\n", bssid);
        ptr = bssid + strlen(bssid) + 1;
        ssid = getValue(ptr, "ssid");
        if (ssid == NULL) 
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: SSID is NULL in Status output\n");
            goto exit;
        }
        printf_decode (stats->sta_SSID, sizeof(stats->sta_SSID), ssid);
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"ssid=%s\n", stats->sta_SSID);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpaCtrlSendCmd(STATUS) failed - Ret = %d \n",retStatus);
    }

    retStatus = wpaCtrlSendCmd("SIGNAL_POLL");
    if(retStatus == 0)
    {
        ptr = getValue(return_buf, "RSSI");
    
        if (ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: RSSI not in signal poll \n");
            goto exit;
        }
        else {
            rssi = atoi(ptr);
            stats->sta_RSSI = rssi; 
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"rssi=%d \n", rssi);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "LINKSPEED");
        if (ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: LINKSPEED not in signal poll \n");
            goto exit;
        }
        else {
            phyrate = atoi(ptr);
            stats->sta_PhyRate = phyrate; 
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"phyrate=%d \n", phyrate);
        }    
    
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "NOISE");
        if (ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: NOISE not in signal poll \n");
            goto exit;
        }
        else {
            noise = atoi(ptr);
            stats->sta_Noise = noise; 
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"noise=%d \n", noise);
        }

        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "FREQUENCY");
        if(ptr == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: FREQUENCY not in signal poll \n");
            goto exit;
        } else  {
            freq = atoi(ptr);
            RDK_LOG( RDK_LOG_DEBUG,LOG_NMGR,"WIFI_HAL: FREQUENCY = %d. \n",freq);
            if((freq / 1000) == 2)
                strcpy(stats->sta_BAND,"2.4GHz");
            else if((freq / 1000) == 5)
                strcpy(stats->sta_BAND,"5GHz");
            else
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Unknown freq band.\n");
            RDK_LOG( RDK_LOG_INFO,LOG_NMGR,"WIFI_HAL: Frequency Band in use = %s \n",stats->sta_BAND);
        }
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpaCtrlSendCmd(SIGNAL_POLL) failed ret = %d\n",retStatus);
    }
exit:
    pthread_mutex_unlock(&wpa_sup_lock);
    return;
}


/**************************************************************************************************/
/*WIFI WPS Related Functions                                                                      */
/**************************************************************************************************/

INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool){
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue){
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong){ //Where does the PIN come from?
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  return RETURN_OK;
}

INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin){
#if 0  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID:%d\n", ssidIndex);
  uint32_t wps_pin = 0;
  if(NetAppWiFiGenerateWPSPin(hNetApp, &wps_pin) == NETAPP_SUCCESS){      //Trying to generate the pin and checking if the result is a success
    pin = wps_pin;
    return RETURN_OK;
  }
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Error setting the device pin\n");
  return RETURN_ERR; 
#endif
return RETURN_OK;
}

INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods){
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //Return all the methods: Push and Pin
 
  if (!is_null_pointer(methods)){
    strcpy(methods, "Push and Pin");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string){
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  //I think returning push and pin for this would be acceptable
  if (!is_null_pointer(output_string)){
    strcpy(output_string, "Push and Pull");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_setCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *methodString){
 
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  if (!is_null_pointer(methodString)){
    strcpy(methodString, "Push and Pin");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Supported Methods: Push and Pin\n");
    return RETURN_OK;
  }
  return RETURN_ERR;
}

INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string){
 
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  return RETURN_OK;
}

INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *EnrolleePin){

 #if 0
  INT* pinValue = 0;
  *pinValue = atoi(EnrolleePin);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  if(NetAppWiFiConnectByPin(hNetApp, NETAPP_IFACE_WIRELESS, NULL, *pinValue, true) == NETAPP_SUCCESS){   //Connecting to the device using a pin and checking the result
    return RETURN_OK;
  }
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Error connecting to device with enrollee pin... Check again\n");
  return RETURN_ERR;
#endif 
return RETURN_OK; 
}

// Parse Scan results and fetch all WPS-PBC enabled accesspoints
int parse_wps_pbc_accesspoints(char *buf,wifi_wps_pbc_ap_t ap_list[])
{
    char  *ptr;
    char ssid[MAX_SSID_LEN+1];
    char bssid[32];
    char rssi[8];
    char freq[8];
    int apCount = 0;
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

    char* line = strtok(ptr, "\n");
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
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS-PBC AccessPoint[%d] : [SSID = %s , BSSID = %s , FREQ = %s , RSSI = %s ]\n",apCount,ssid,bssid,freq,rssi);
                strncpy(ap_list[apCount].ap_BSSID,bssid,sizeof(ap_list[apCount].ap_BSSID));
                strncpy(ap_list[apCount].ap_SSID,ssid,sizeof(ap_list[apCount].ap_SSID));
                ap_list[apCount].ap_Frequency = (int) strtol(freq,&eptr,10);
                ap_list[apCount].ap_FreqBand = (((ap_list[apCount].ap_Frequency/1000) == 5)?WIFI_HAL_FREQ_BAND_5GHZ:WIFI_HAL_FREQ_BAND_24GHZ);
                ap_list[apCount].ap_SignalStrength = (int) strtol(rssi,&eptr,10);
                apCount++;
            }
        }
        line = strtok(NULL, "\n");
    }
    return apCount;
}

// Cancel the WPS operation 
void stop_wifi_wps_connection()
{
    if(bIsWpsCompleted == FALSE)
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Stopping  WPS operation.. \n");
        pthread_cancel(wps_start_thread); // Lets forcefully stop the thread as we need to strictly maintain WPS time frame

        // Make sure that the mutex is not locked by wps thread & Cancel WPS operation
        if(pthread_mutex_trylock(&wpa_sup_lock) != 0)
        {
            pthread_mutex_unlock(&wpa_sup_lock);
            pthread_mutex_lock(&wpa_sup_lock);
        }
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
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"TELEMETRY_WPS_CONNECTION_STATUS:DISCONNECTED,WPS_PBC_OVERLAP");
        else
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"TELEMETRY_WPS_CONNECTION_STATUS:DISCONNECTED,WPS_TIME_OUT");
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
    if(fp != NULL)
    {
        if((fgets(result,BUFF_LEN_64-1,fp)!=NULL) && (result[0] != '\0') )
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
        fclose(fp);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: isDualBandSupported() : popen() failed \n");
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
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Initiating WPS connection to BSSID - %s \n",bssid );
        pthread_mutex_lock(&wpa_sup_lock);
        retStatus = wpaCtrlSendCmd(cmd);
        pthread_mutex_unlock(&wpa_sup_lock);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: triggerWpsPush() failed , BSSID is NULL.! \n");
    }
    return retStatus;
}

// Start WPS operation with Band selection.
void start_wifi_wps_connection(void *param)
{
    int apCount = 0;
    int i = 0;
    wifi_wps_pbc_ap_t ap_list[MAX_WPS_AP_COUNT];
    char tmpBuff[RETURN_BUF_LENGTH];
    int retry = 0;
    bIsWpsCompleted = FALSE;
    bIsPBCOverlapDetected = FALSE;

    // Continue scanning & try connecting Until WPS is successfull
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scanning for WPS-PBC access points on both 5 & 2.4 GHz Bands.\n");
    while(!bIsWpsCompleted) 
    {
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("BSS_FLUSH 0");
        bNoAutoScan = TRUE;
        wpaCtrlSendCmd("SCAN");

        // Check if scanning is failed due to in progress scanning
        if (strstr(return_buf, "FAIL-BUSY") != NULL) {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: FAIL-BUSY due to in-progress scanning..  \n");
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
        bNoAutoScan=FALSE;
        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
        apCount = parse_wps_pbc_accesspoints(tmpBuff,ap_list);
        if(apCount != 0)
        {
            // Trying to get 5Ghz PBC enabled Accesspoints from scnaned list and start wps operation
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Trying to establish WPS connection to 5GHz Accesspoint.\n");
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
                       RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to connect to 5G AP - %s\n",ap_list[i].ap_SSID);
                    else {
                       // Adding Telemetry for Successful connection
                       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"TELEMETRY_WPS_CONNECTION_STATUS:CONNECTED,%s,%s,5GHz,%d,%d \n",ap_list[i].ap_SSID,ap_list[i].ap_BSSID,ap_list[i].ap_SignalStrength,ap_list[i].ap_Frequency);
                       return ;
                    }
                }
            }

            // Looks like either we couldnt get a 5G AP or we couldnt connected to 5G AP. Lets try to connect to 2.4 G AP
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Failed to get 5Ghz AP for WPS connection, Trying for 2.4GHz AP. \n");
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
                        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to connect to 2.4G AP - %s\n",ap_list[i].ap_SSID);
                    else {
                        // Adding Telemetry for Successful Connection
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"TELEMETRY_WPS_CONNECTION_STATUS:CONNECTED,%s,%s,2.4GHz,%d,%d \n",ap_list[i].ap_SSID,ap_list[i].ap_BSSID,ap_list[i].ap_SignalStrength,ap_list[i].ap_Frequency);
                        return;
                    }
                }
            }
        } // End Of if(apCount != 0)
        else
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Missing WPS_PBC AP in Scanned list, Continue Scanning...  \n");
        }
    } // End of while(!bIsWpsCompleted)
}

INT wifi_setCliWpsButtonPush(INT ssidIndex){
 
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
  
  size_t return_len=sizeof(return_buf)-1;                                                                /* Return length of the buffer */
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPS Push Button Call\n");
  
  pthread_mutex_lock(&wpa_sup_lock);
  
  if (cur_sup_state != WIFI_HAL_WPA_SUP_STATE_IDLE) {
        pthread_mutex_unlock(&wpa_sup_lock);
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connection is in progress, returning error \n");
        return RETURN_ERR;
  }

  isPrivateSSID=1;
  wpaCtrlSendCmd("REMOVE_NETWORK 0");
  wpaCtrlSendCmd("SAVE_CONFIG");
  bUpdatedSSIDInfo=1;
  pthread_mutex_unlock(&wpa_sup_lock);
 
  if(isDualBandSupported())
 {
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: STB is Dual-Band supported. Initiating band seletion... \n");
      pthread_create(&wps_start_thread, NULL, start_wifi_wps_connection, NULL);
      // Start WPS timer
      signal(SIGALRM, stop_wifi_wps_connection);
      alarm(WPS_CON_TIMEOUT);
  }   
  else
  {
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: No Dual-Band support. Initiate Normal PBC.\n");
      pthread_mutex_lock(&wpa_sup_lock);
      wpaCtrlSendCmd("WPS_PBC");
      pthread_mutex_unlock(&wpa_sup_lock);
  }

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Will be timing out if AP not found after 120 seconds\n");

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Deleting conf file and making a new one\n");

  if(remove("/opt/wifi/wpa_supplicant.conf") == 0){
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Removed File\n");
  }

  FILE* fp;
  fp = fopen("/opt/wifi/wpa_supplicant.conf", "w");
  if(fp == NULL){
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Error in opening configuration file\n");
    return RETURN_ERR;
  }
  fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
  fprintf(fp, "update_config=1\n");
  fclose(fp);

  wifiStatusCode_t connError;
  connError = WIFI_HAL_CONNECTING;
  (*callback_connect)(1, "", &connError);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connection in progress..\n");
   
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI HAL: WPS Push sent successfully\n");
  return RETURN_OK;
}

INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int saveSSID,CHAR * eapIdentity,CHAR * carootcert,CHAR * clientcert,CHAR * privatekey){
  
  int retStatus = -1;
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex);
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Save SSID value:%d\n", saveSSID);

  pthread_mutex_lock(&wpa_sup_lock);          /* Locking in the mutex before connect */
  isPrivateSSID=saveSSID;
  if (isPrivateSSID) {
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Will save network to wpa_supplicant.conf if connect is successful\n");
  }
  else { // LnF SSID
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Will not save network to wpa_supplicant.conf\n");
  }


  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Requesting connection to AP\n");
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL:Security mode:%d\n", AP_security_mode);
  retStatus=wpaCtrlSendCmd("REMOVE_NETWORK 0");
  if ((strstr (return_buf, "FAIL") != NULL) || (retStatus != 0))
  {
      RDK_LOG (RDK_LOG_ERROR, LOG_NMGR, "WIFI_HAL: %s: REMOVE_NETWORK 0 failed error %d  \n", __FUNCTION__,retStatus);
  }
  
  wpaCtrlSendCmd("ADD_NETWORK");

  wpaCtrlSendCmd("SET_NETWORK 0 auth_alg OPEN");
  
  /* Set SSID */
  sprintf(cmd_buf, "SET_NETWORK 0 ssid \"%s\"", AP_SSID);
  wpaCtrlSendCmd(cmd_buf);
  
  if((AP_security_mode == WIFI_SECURITY_WPA_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA_PSK_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA2_PSK_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_WPA2_PSK)){
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Security mode is PSK\n");
      /* Key Management */
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt WPA-PSK");
      wpaCtrlSendCmd(cmd_buf);
      /* Set the PSK */
      sprintf(cmd_buf, "SET_NETWORK 0 psk \"%s\"", AP_security_PreSharedKey);
      wpaCtrlSendCmd(cmd_buf);
      if(strstr(return_buf, "FAIL") != NULL){
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Password may not be falling within spec\n");
        wifiStatusCode_t connError;
        connError = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
        (*callback_connect)(1, AP_SSID, &connError);
        pthread_mutex_unlock(&wpa_sup_lock);
        if (!isPrivateSSID)
        {
            isPrivateSSID = 1;
        }
        return RETURN_OK;
      }
  }
  else if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA_WPA2_ENTERPRISE) ){
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Security mode is WPA Enterprise\n");
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt WPA-EAP");
      wpaCtrlSendCmd(cmd_buf);
  }
  else{
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: None\n");
      sprintf(cmd_buf, "SET_NETWORK 0 key_mgmt NONE");
      wpaCtrlSendCmd(cmd_buf);
//      sprintf(cmd_buf, "SET_NETWORK 0 wep_key0 \"%s\"", AP_security_KeyPassphrase);
//      wpaCtrlSendCmd(cmd_buf);
  }
  
  /* Allow us to connect to hidden SSIDs */
  wpaCtrlSendCmd("SET_NETWORK 0 scan_ssid 1");
      
  if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP) ||
      (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES)|| (AP_security_mode == WIFI_SECURITY_WPA_WPA2_ENTERPRISE) || (AP_security_mode == WIFI_SECURITY_WPA_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES) || (AP_security_mode == WIFI_SECURITY_WPA_WPA2_PSK)){
          
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Setting TKIP values\n");
    
      wpaCtrlSendCmd("SET_NETWORK 0 pairwise CCMP TKIP");
          
      wpaCtrlSendCmd("SET_NETWORK 0 group CCMP TKIP");
          
      wpaCtrlSendCmd("SET_NETWORK 0 proto WPA RSN");
  }
  
  if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP) || (AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES) || (AP_security_mode == WIFI_SECURITY_WPA_WPA2_ENTERPRISE)){
    
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL:EAP Identity %s\n", eapIdentity);
      sprintf(cmd_buf, "SET_NETWORK 0 identity \"%s\"", eapIdentity);
      
      wpaCtrlSendCmd(cmd_buf);

      wpaCtrlSendCmd("SET_NETWORK 0 eap TLS");
  }
  
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The carootcert:%s\n", carootcert);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The clientcert:%s\n", clientcert);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: The privatekey:%s\n", privatekey);
  RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: The PSK key:%s\n", AP_security_PreSharedKey);
  RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: The KeyP key:%s\n", AP_security_KeyPassphrase);
  
  /* EAP with certificates */
  if (access(carootcert, F_OK) != -1){
      
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: CA Root certificate exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 ca_cert \"%s\"", carootcert);
      wpaCtrlSendCmd(cmd_buf);
  }

  if (access(clientcert, F_OK) != -1){
      
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Client Certificate exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 client_cert \"%s\"", clientcert);
      wpaCtrlSendCmd(cmd_buf);
  }

  if (access(privatekey, F_OK) != -1){
      
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Private Key exists\n");
      sprintf(cmd_buf, "SET_NETWORK 0 private_key \"%s\"", privatekey);
      wpaCtrlSendCmd(cmd_buf);
      
      sprintf(cmd_buf, "SET_NETWORK 0 private_key_passwd \"%s\"", AP_security_KeyPassphrase);
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Command is:%s\n", cmd_buf);
      wpaCtrlSendCmd(cmd_buf);
  }
  
  wpaCtrlSendCmd("SET_NETWORK 0 mode 0");
  
  snprintf (ssid_to_find, sizeof (ssid_to_find), "%s", AP_SSID);
  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Setting ssid_to_find to [%s]\n", ssid_to_find);
  
  wpaCtrlSendCmd("ENABLE_NETWORK 0");
  wpaCtrlSendCmd("REASSOCIATE");
  
  if(saveSSID){
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Connecting to the specified access point\n");
    wifiStatusCode_t connError;
    connError = WIFI_HAL_CONNECTING;
    if (callback_connect) (*callback_connect)(1, AP_SSID, &connError);    
  }    

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Leaving WiFi Connect Endpoint function\n");
  pthread_mutex_unlock(&wpa_sup_lock);
  return RETURN_OK;
}

INT wifi_lastConnected_Endpoint(wifi_pairedSSIDInfo_t *pairedSSIDInfo){
    char buf[512];
    static char ssid[32]={0};
    static char bssid[20]={0};
    static char security[64]={0};
    static char passphrase[64]={0};
    char *tokenKey;
    char *tokenValue;
    FILE *f = NULL;

    if(!bUpdatedSSIDInfo)
    {
        strcpy(pairedSSIDInfo->ap_ssid, ssid);
        strcpy(pairedSSIDInfo->ap_bssid, bssid);
        strcpy(pairedSSIDInfo->ap_security, security);
        strcpy(pairedSSIDInfo->ap_passphrase,passphrase);
        return RETURN_OK;
    }
    f = fopen("/opt/wifi/wpa_supplicant.conf", "r");
    if(NULL == f)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to open wpa_supplicant.conf\n");
        return RETURN_ERR;
    }
    while( fgets(buf, 512, f) != NULL) {
        tokenKey=strtok(buf,"\"=");
        tokenValue=strtok(NULL,"\"=");
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
    }
    fclose(f);

    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: %s: ap_ssid=[%s], ap_bssid=[%s]\n",
            __FUNCTION__, pairedSSIDInfo->ap_ssid, pairedSSIDInfo->ap_bssid);

    // BSSID will be empty if wpa_supplicant.conf does not have it
    // in this case, get BSSID from output of wpa control interface command "STATUS"
    // but use BSSID from "STATUS" only if SSID from "STATUS" = SSID from conf file (as any SSID not in conf file should be ignored)
    if (pairedSSIDInfo->ap_ssid[0] != '\0' && pairedSSIDInfo->ap_bssid[0] == '\0') // wpa_supplicant.conf file has SSID but not BSSID
    {
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("STATUS");
        const char* current_bssid = getValue(return_buf, "bssid");
        RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: %s: current_bssid=[%s]\n", __FUNCTION__, current_bssid);
        if (current_bssid)
        {
            const char *ssid_ptr = getValue((char*) (strchr(current_bssid, '\0') + 1), "ssid"); // look for ssid after end of bssid
            RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: %s: ssid_ptr=[%s]\n", __FUNCTION__, ssid_ptr);
            if (ssid_ptr)
            {
                char current_ssid[MAX_SSID_LEN+1] = {0};
                printf_decode (current_ssid, sizeof(current_ssid), ssid_ptr);
                RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: %s: current_ssid=[%s]\n", __FUNCTION__, current_ssid);
                if (strcmp(pairedSSIDInfo->ap_ssid, current_ssid) == 0)
                {
                    snprintf (pairedSSIDInfo->ap_bssid, sizeof(pairedSSIDInfo->ap_bssid), "%s", current_bssid);
                    snprintf (bssid, sizeof(bssid), "%s", current_bssid);
                    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: %s: current_ssid matches ap_ssid. ap_bssid set to [%s]\n",
                            __FUNCTION__, pairedSSIDInfo->ap_bssid);
                }
            }
        }
        pthread_mutex_unlock(&wpa_sup_lock);
    }

    return RETURN_OK;
}

INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID){

 RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID Index is not applicable here since this is a STA.. Printing SSID Index:%d\n", ssidIndex); 
 
 RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Received request to disconnect from AP\n");
 
 wpaCtrlSendCmd("DISCONNECT");
 
 return RETURN_OK;
}

//Callback registration function.

void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc){

  RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Registering connect callback...\n");
  callback_connect=callback_proc;

}

//Callback registration function.
void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc){

   RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Registering disconnect callback...\n");
   callback_disconnect=callback_proc;
}


#ifdef WIFI_CLIENT_ROAMING
int wifi_setRoamingControl (int ssidIndex, wifi_roamingCtrl_t *pRoamingCtrlCfg)
{
    wifi_roamingCtrl_t currentCfg;
    int status = -1;
    char cmd[64];

    if(NULL == pRoamingCtrlCfg) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Input pointer is NULL \n");
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
            if(status != 0) {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to set roaming enable.! \n");
                return RETURN_ERR;
            }
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Successfully set roamingEnable to %d\n", pRoamingCtrlCfg->roamingEnable);
         } else {
             RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: Trying to set same value for roamingEnable, Ignoring SET operation.\n");
         }

         // Check Roaming is enabled Or Not, If Not DONOT Allow to SET/GET
         if(pRoamingCtrlCfg->roamingEnable == 0 && currentCfg.roamingEnable == 0) {
             RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Romaing Feature is not enabled, Ignoring SET request.!\n");
             return -2;
          }
         if(currentCfg.preassnBestThreshold != pRoamingCtrlCfg->preassnBestThreshold && pRoamingCtrlCfg->preassnBestThreshold <= 0 && pRoamingCtrlCfg->preassnBestThreshold >= -200) {
            snprintf(cmd_buf, sizeof(cmd_buf), "SET pre_assn_best_threshold_level %d", pRoamingCtrlCfg->preassnBestThreshold);
            pthread_mutex_lock(&wpa_sup_lock);
            status = wpaCtrlSendCmd(cmd_buf);
            pthread_mutex_unlock(&wpa_sup_lock);
            if(status != 0) {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to set pre_assn_best_threshold_level.! \n");
                return RETURN_ERR;
            }
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Successfully set preassnBestThreshold to %d\n", pRoamingCtrlCfg->preassnBestThreshold);
         } else if(currentCfg.preassnBestThreshold == pRoamingCtrlCfg->preassnBestThreshold)
             RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: Trying to set same value for preassnBestThreshold, Ignoring SET operation.\n");
         else{
             RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to set pre_assn_best_threshold_level - Invalid value = %d \n",pRoamingCtrlCfg->preassnBestThreshold);
             return RETURN_ERR;
         }

         if(currentCfg.preassnBestDelta != pRoamingCtrlCfg->preassnBestDelta) {
            snprintf(cmd_buf, sizeof(cmd_buf), "SET pre_assn_best_delta_level %d", pRoamingCtrlCfg->preassnBestDelta);
            pthread_mutex_lock(&wpa_sup_lock);
            status = wpaCtrlSendCmd(cmd_buf);
            pthread_mutex_unlock(&wpa_sup_lock);
            if(status != 0) {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to set pre_assn_best_delta_level.! \n");
                return RETURN_ERR;
            }
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Successfully set preassnBestDelta to %d\n", pRoamingCtrlCfg->preassnBestDelta);
         } else {
             RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: Trying to set same value for preassnBestDelta, Ignoring SET operation.\n");
         }

         // Save the current values to persistent file
         status = persist_roaming_config(pRoamingCtrlCfg);
         pthread_mutex_lock(&wpa_sup_lock);
         wpaCtrlSendCmd("SAVE_CONFIG");
         pthread_mutex_unlock(&wpa_sup_lock);
         if(status != 0)
             RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to save roaming onfiguration.! \n");
         
    } else {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to get current romaing Config \n");
    }
    return status;
}   

int persist_roaming_config(wifi_roamingCtrl_t* pRoamingCtrl_data)
{
    cJSON *pRoamingCtrl_Json_Data = NULL;
    int retValue = 0;
    
    if (pRoamingCtrl_data != NULL) {
        pRoamingCtrl_Json_Data = cJSON_CreateObject();
        if(!pRoamingCtrl_Json_Data) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to create JSON object \n");
            return RETURN_ERR;
        }

        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "roamingEnable", pRoamingCtrl_data->roamingEnable);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "preassnBestThreshold", pRoamingCtrl_data->preassnBestThreshold);
        cJSON_AddNumberToObject(pRoamingCtrl_Json_Data, "preassnBestDelta", pRoamingCtrl_data->preassnBestDelta);

        if( writeToPersistentFile(WIFI_ROAMING_CONFIG_FILE , pRoamingCtrl_Json_Data) != 0)
            retValue = -1;
        cJSON_Delete(pRoamingCtrl_Json_Data);
    } else {
       retValue = -1;
       RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Input config is NULL, failed to save roaming config \n");
    }
    return retValue;
}
int wifi_getRoamingControl(INT ssidIndex, wifi_roamingCtrl_t *pRoamingCtrlCfg)
{
    char* ptr = NULL;
    int retStatus = RETURN_OK;

    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: Entering ... (%s) \n",__FUNCTION__);

    if(pRoamingCtrlCfg == NULL) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Input Stats is NULL \n");
        return RETURN_ERR;
    }
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("GET roaming_controls");
    if(retStatus == 0)
    {
        ptr = getValue(return_buf, "roaming_enable");
        if (ptr == NULL) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in getting roaming_enable. \n");
            retStatus = RETURN_ERR;
            goto exit_err;
        }
        else {
            pRoamingCtrlCfg->roamingEnable = strtol(ptr,NULL,10);
            RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: [%s] Roaming Enable = %d\n",__FUNCTION__,pRoamingCtrlCfg->roamingEnable);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "pre_assn_best_threshold_level");
        if (ptr == NULL) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in getting pre_assn_best_threshold_level. \n");
            retStatus = RETURN_ERR;
            goto exit_err;
        }
        else {
            pRoamingCtrlCfg->preassnBestThreshold = strtol(ptr,NULL,10);
            RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: [%s] preassnBestThreshold  = %d\n",__FUNCTION__,pRoamingCtrlCfg->preassnBestThreshold);
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "pre_assn_best_delta_level");
        if (ptr == NULL) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in getting pre_assn_best_delta_level. \n");
            retStatus = RETURN_ERR;
            goto exit_err;
        }
        else {
            pRoamingCtrlCfg->preassnBestDelta = strtol(ptr,NULL,10);
            RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: [%s] preassnBestDelta = %d\n",__FUNCTION__,pRoamingCtrlCfg->preassnBestDelta);
        }

    } else {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: GET ROAMING_CONTROLS failed , Status = %d \n",retStatus);
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
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to open persistent file. !\n ");
        }
        else
        {
            int ch_count = 0;
            fseek(fp, 0, SEEK_END);
            ch_count = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            fileContent = (char *) malloc(sizeof(char) * (ch_count + 1));
            if(fileContent == NULL) {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to allocate memory, readPersistentFile failed.\n ");
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
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Missing persistent file!\n ");
    }
    return fileContent;
}
int writeToPersistentFile (char* fileName, cJSON* pRoaming_Data)
{
    FILE *fp = NULL;
    fp = fopen(fileName, "w");
    if (fp == NULL)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to open persistent file. !\n ");
        return -1;
    }
    else
    {
        char* fileContent = cJSON_Print(pRoaming_Data);
        if(fileContent != NULL) {
            fprintf(fp, "%s", fileContent);
            free(fileContent);
            RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: Persistent file saved successfully.\n ");
        } else {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to format Json to string. !\n ");
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

    // Read RFC Params and update


    pRoamingCtrl_data_file_content = readPersistentFile(WIFI_ROAMING_CONFIG_FILE);
    // check if file is empty
    if(NULL == pRoamingCtrl_data_file_content) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to read persistent file. !\n ");
        return RETURN_ERR;
    }
    if(pRoamingCtrl_data_file_content) {
        pRoamingCtrl_json = cJSON_Parse(pRoamingCtrl_data_file_content);
        free(pRoamingCtrl_data_file_content);
    }
     
    if(NULL == pRoamingCtrl_json) {
         RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failed to parse configuration file !\n ");
         return RETURN_ERR;
    }
    else {
        
        if( !(cJSON_GetObjectItem(pRoamingCtrl_json,"roamingEnable")) || !(cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestThreshold") || !(cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestDelta")))) {
             RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Corrupted roaming values, Unable to load intial configs !\n ");
             return RETURN_ERR;
        }
        pRoamingCtrl_data.roamingEnable = cJSON_GetObjectItem(pRoamingCtrl_json,"roamingEnable")->valueint;
        pRoamingCtrl_data.preassnBestThreshold = cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestThreshold")->valueint;
        pRoamingCtrl_data.preassnBestDelta = cJSON_GetObjectItem(pRoamingCtrl_json,"preassnBestDelta")->valueint;
        cJSON_Delete(pRoamingCtrl_json);

        // Setting intial config values 
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Setting Initial Roaming Configuration :- [roamingEnable=%d,preassnBestThreshold=%d,preassnBestDelta=%d]\n",pRoamingCtrl_data.roamingEnable,pRoamingCtrl_data.preassnBestThreshold,pRoamingCtrl_data.preassnBestDelta);
        wifi_setRoamingControl(ssidIndex,&pRoamingCtrl_data);
    }
    return RETURN_OK;
}
#endif
