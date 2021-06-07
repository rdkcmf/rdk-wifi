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
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <wifi_common_hal.h>
#include <stdbool.h>
#include "rdk_debug.h"

#define LOG_NMGR "LOG.RDK.WIFIHAL"
#define MAX_SSID_LEN        32           /* Maximum SSID name */
#define MAX_VERSION_LEN     16          /* Maximum Version Len */
#define BUFF_LEN_1024       1024
extern BOOL bNoAutoScan;

ULONG ssid_number_of_entries = 0;

/*! Supported values are NONE - 0, WPA - 1, WEP - 2*/
typedef enum _SsidSecurity
{
    NET_WIFI_SECURITY_NONE = 0,
    NET_WIFI_SECURITY_WEP_64,
    NET_WIFI_SECURITY_WEP_128,
    NET_WIFI_SECURITY_WPA_PSK_TKIP,
    NET_WIFI_SECURITY_WPA_PSK_AES,
    NET_WIFI_SECURITY_WPA2_PSK_TKIP,
    NET_WIFI_SECURITY_WPA2_PSK_AES,
    NET_WIFI_SECURITY_WPA_ENTERPRISE_TKIP,
    NET_WIFI_SECURITY_WPA_ENTERPRISE_AES,
    NET_WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,
    NET_WIFI_SECURITY_WPA2_ENTERPRISE_AES,
    NET_WIFI_SECURITY_NOT_SUPPORTED = 15,
} SsidSecurity;

/*static struct _wifi_securityModes
{
    SsidSecurity 	securityMode;
    const char          *modeString;
} wifi_securityModes[] =
{
    { NET_WIFI_SECURITY_NONE,          		    "No Security"                   },
    { NET_WIFI_SECURITY_WEP_64, 	            "WEP (Open & Shared)"        	},
    { NET_WIFI_SECURITY_WEP_128,                "WEP (Open & Shared)"           },
    { NET_WIFI_SECURITY_WPA_PSK_TKIP, 		 	"WPA-Personal, TKIP encryp."   	},    
    { NET_WIFI_SECURITY_WPA_PSK_AES, 		  	"WPA-Personal, AES encryp."    	},
    { NET_WIFI_SECURITY_WPA2_PSK_TKIP, 			"WPA2-Personal, TKIP encryp."  	},
    { NET_WIFI_SECURITY_WPA2_PSK_AES,  			"WPA2-Personal, AES encryp."   	},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_TKIP,	"WPA-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_AES,		"WPA-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,		"WPA2-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_AES,		"WPA2-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_NOT_SUPPORTED, 		  	"Security format not supported" },
};*/

static struct _wifi_securityModes
{
    const char          *modeString;
    const char          *encryptionString;
    const char          *apSecurityEncryptionString;
} wifi_securityModes[] =
{
    { "WPA2-SAE-CCMP","SAE","[WPA2-SAE-CCMP]" },
    { "WPA2-PSK+SAE-CCMP","AES","[WPA2-PSK+SAE-CCMP]" },
    { "WPA-WPA2","TKIP","[WPA-PSK-TKIP][WPA2-PSK-TKIP]"},
    { "WPA-WPA2","AES","[WPA-PSK-CCMP][WPA2-PSK-CCMP]"},
    { "WPA-WPA2","TKIP,AES","[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP]"},
    { "WPA-WPA2-Enterprise","TKIP","[WPA-EAP-TKIP][WPA2-EAP-TKIP]"},
    { "WPA-WPA2-Enterprise","AES","[WPA-EAP-CCMP][WPA2-EAP-CCMP]"},
    { "WPA-WPA2-Enterprise","TKIP,AES","[WPA-EAP-CCMP+TKIP][WPA2-EAP-CCMP+TKIP]"},
    { "WPA-Enterprise","TKIP,AES","[WPA-EAP-CCMP+TKIP]"},
    { "WPA2-Enterprise","TKIP,AES","[WPA2-EAP-CCMP+TKIP]"},
    { "WPA-Enterprise","TKIP","[WPA-EAP-TKIP]"},
    { "WPA-Enterprise","AES","[WPA-EAP-CCMP]"},
    { "WPA2-Enterprise","TKIP","[WPA2-EAP-TKIP]"},
    { "WPA2-Enterprise","AES","[WPA2-EAP-CCMP]"},
    { "WPA","TKIP","[WPA-PSK-TKIP]"},
    { "WPA2","TKIP","[WPA2-PSK-TKIP]"},
    { "WPA","AES","[WPA-PSK-CCMP]"},
    { "WPA2","AES","[WPA2-PSK-CCMP]"},
    { "WPA","TKIP,AES","[WPA-PSK-CCMP+TKIP]"},
    { "WPA2","TKIP,AES","[WPA2-PSK-CCMP+TKIP]"},
    { "WEP","","WEP"},
    { "None","","None"},
};
/*{
    { NET_WIFI_SECURITY_NONE,          		    "No Security"                   },
    { NET_WIFI_SECURITY_WEP_64, 	            "WEP (Open & Shared)"        	},
    { NET_WIFI_SECURITY_WEP_128,                "WEP (Open & Shared)"           },
    { NET_WIFI_SECURITY_WPA_PSK_TKIP, 		 	"WPA-Personal, TKIP encryp."   	},    
    { NET_WIFI_SECURITY_WPA_PSK_AES, 		  	"WPA-Personal, AES encryp."    	},
    { NET_WIFI_SECURITY_WPA2_PSK_TKIP, 			"WPA2-Personal, TKIP encryp."  	},
    { NET_WIFI_SECURITY_WPA2_PSK_AES,  			"WPA2-Personal, AES encryp."   	},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_TKIP,	"WPA-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA_ENTERPRISE_AES,		"WPA-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,		"WPA2-ENTERPRISE, TKIP"		},
    { NET_WIFI_SECURITY_WPA2_ENTERPRISE_AES,		"WPA2-ENTERPRISE, AES"		},
    { NET_WIFI_SECURITY_NOT_SUPPORTED, 		  	"Security format not supported" },
};*/
 
INT is_null_pointer(char* str) {    //Check if passed string is a null pointer and empty string or not
    if ((str !=NULL) && (str[0]=='\0')) {
        return 0;
    }
    return 1;
}

#include <wpa_ctrl.h>

#include <stdint.h>
typedef uint8_t u8;
// added to be able to use wpa_supplicant's 'printf_decode' utility function to decode the SSIDs encoded by wpa_supplicant
extern size_t printf_decode(u8 *buf, size_t maxlen, const char *str);

#define BUF_SIZE               256

#define CA_ROOT_CERT_PATH      "/opt/lnf/ca-chain.cert.pem"
#define CA_CLIENT_CERT_PATH    "/opt/lnf/xi5device.cert.pem"
#define CA_PRIVATE_KEY_PATH    "/opt/lnf/xi5device.key.pem"
#define WPA_SUP_CONFIG         "/opt/secure/wifi/wpa_supplicant.conf"

#define WPA_SUP_PIDFILE         "/var/run/wpa_supplicant/wlan0.pid"
#define WPA_SUP_CTRL            "/var/run/wpa_supplicant/wlan0"

#define WPA_SUP_TIMEOUT         7000   /* 7 msec */
#define WPA_SUP_PING_INTERVAL   60 /* 1 min */

typedef enum {
    WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE,
    WIFI_HAL_WPA_SUP_SCAN_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED,
    WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED,
} WIFI_HAL_WPA_SUP_SCAN_STATE;

char* getValue(char *buf, char *keyword);
int wpaCtrlSendCmd(char *cmd);
int get_wifi_self_steer_matching_bss_list(char* ssid_to_find,wifi_neighbor_ap_t neighborAPList[],int timeout);
static INT getFrequencyListFor_Band(WIFI_HAL_FREQ_BAND band, char *output_string);
BOOL isDualBandSupported();
#ifdef WIFI_CLIENT_ROAMING
int initialize_roaming_config();
#endif

bool init_done=false;   /* Flag to check if WiFi init was already done or not */
extern bool stop_monitor;  /* Flag to stop the monitor thread */
uint32_t g_wpa_sup_pid=0, ap_count=0;
struct wpa_ctrl *g_wpa_ctrl= NULL;
struct wpa_ctrl *g_wpa_monitor = NULL; 
WIFI_HAL_WPA_SUP_SCAN_STATE cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
pthread_mutex_t wpa_sup_lock;
char cmd_buf[1024], return_buf[16384];
char event_buf[4096];
wifi_neighbor_ap_t ap_list[512];

pthread_t monitor_thread;
pthread_t wpa_health_mon_thread;
void monitor_thread_task(void *param);
void monitor_wpa_health();
static int wifi_getWpaSupplicantStatus();
static int wifi_openWpaSupConnection();
static INT wifi_getRadioSignalParameter (const CHAR* parameter, CHAR *output_string);


INT wifi_getHalVersion(CHAR *output_string)
{
    int retStatus  = RETURN_OK;
    int ret = 0;
    if(output_string) {
        ret = sprintf(output_string,"%d.%d.%d",WIFI_HAL_MAJOR_VERSION,WIFI_HAL_MINOR_VERSION,WIFI_HAL_MAINTENANCE_VERSION);
        if(ret <= 0 || ret > MAX_VERSION_LEN) { 
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Failed generate HAL Version, ret = %d.\n",ret );
            retStatus = RETURN_ERR;
         }
    } else {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Failed to get HAL Version - Input String is NULL.\n" );
        retStatus = RETURN_ERR;
    } 
    return retStatus;
}
static INT getFrequencyListFor_Band(WIFI_HAL_FREQ_BAND band, char *output_string)
{
    if(output_string == NULL)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"[%s] Memory not allocated for output_string \n",__FUNCTION__);
        return RETURN_ERR;
    }
    char *s,*t,*r;
    char lines[32][64];
    int i,k;
    INT ret = RETURN_ERR;
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: in getFrequencyListFor_Band ..\n");
    pthread_mutex_lock(&wpa_sup_lock);
    int ret_status = wpaCtrlSendCmd("GET_CAPABILITY freq");
    if(ret_status == RETURN_OK)
    {
        if( band == WIFI_HAL_FREQ_BAND_5GHZ)
        {
            s = strstr(return_buf, "Mode[A] Channels:");
            t = strstr(return_buf, "Mode[B] Channels:");
            if(t) *t = NULL;
        }
        else if (band == WIFI_HAL_FREQ_BAND_24GHZ)
        {
            s = strstr(return_buf, "Mode[G] Channels:");
            t = strstr(return_buf, "Mode[A] Channels:");
            if(t) *t = NULL;
        }
        if (s == NULL)
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"[%s] Error in selecting the frequencies\n",__FUNCTION__);
            ret = RETURN_ERR;
        }
        else
        {
            s = s+18;
            r = strtok(s,"\n");
            i=0;
            while(r != NULL)
            {
                strcpy(lines[i],r);
                r = strtok(NULL,"\n");
                i++;
            }
            for(int k=0;k<i;k++)
            {
                char *ptr = lines[k];
                strtok_r(ptr,"=", &ptr);
                char *tmp = strtok(ptr," ");
                strcpy(lines[k],tmp);
                strcat(output_string,lines[k]);
                strcat(output_string, " ");
            }
            RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"frequencies selected : [%s] \n",output_string);
            ret = RETURN_OK;
        }
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"[%s] Error in getting supported bands- Unable to get Channel Capability\n",__FUNCTION__);
        ret = RETURN_ERR;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return ret;
    //wpa_cli get_capability freq
}

char* readFile(char *filename)
{
    FILE    *fp = NULL;
    char    *buf = NULL;
    long    fBytes = 0;
    long    freadBytes = 0; 

    fp=fopen(filename,"r");
    if(fp==NULL)
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"readFile(): File Open Error \n" );
        return NULL;
    }
    fseek(fp,0L,SEEK_END);
    fBytes=ftell(fp);
    fseek(fp,0L,SEEK_SET);
    if(fBytes > 0)
    {
        buf=(char *)calloc(fBytes+1,sizeof(char));
        if(buf == NULL)
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"readFile(): Memory Allocation Error \n" );
            fclose(fp);
            return NULL; 
        }
        freadBytes = fread(buf,sizeof(char),fBytes,fp);
        if(freadBytes != fBytes) // Do we need to proceed on partial read.. ? Blocking for now.
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR," readFile(): Error occured during fread(), freadBytes= %d  \n" ,freadBytes); 
            fclose(fp);
            free(buf);
            return NULL;
        }
    }
    else
    {
       RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"readFile(): File is empty \n" );
    }
    fclose(fp);
    return buf;
}

// Initializes the wifi subsystem (all radios)
INT wifi_init() {
    int retry = 0;
    stop_monitor=false;
    pthread_attr_t thread_attr;
    int ret;

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Initializing Generic WiFi hal.\n");
    if(init_done == true) {
       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Wifi init has already been done\n");
       return RETURN_OK;
    }
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: TELEMETRY_WIFI_WPA_SUPPLICANT:ENABLED \n ");    
   
    // Starting wpa_supplicant service if it is not already started
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Starting wpa_supplicant service \n ");
#ifndef RDKC
    system("systemctl start wpa_supplicant");
#else
   system("/etc/init.d/wpa_supplicant.service restart");
#endif

    /* Starting wpa_supplicant may take some time, try 10 times before giving up */
    retry = 0;    
    while (retry++ < 10) {
        g_wpa_ctrl = wpa_ctrl_open(WPA_SUP_CTRL);
        if (g_wpa_ctrl != NULL) break;
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"ctrl_open returned NULL \n");
        sleep(1);
    }

    if (g_wpa_ctrl == NULL) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_ctrl_open failed for control interface \n");
        return RETURN_ERR;
    }
    g_wpa_monitor = wpa_ctrl_open(WPA_SUP_CTRL);
    if ( g_wpa_monitor == NULL ) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_ctrl_open failed for monitor interface \n");
        return RETURN_ERR;
    }

    if ( wpa_ctrl_attach(g_wpa_monitor) != 0) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_ctrl_attach failed \n");
        return RETURN_ERR;
    }
    if (pthread_mutex_init(&wpa_sup_lock, NULL) != 0)
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: mutex init failed\n");
        return RETURN_ERR;
    }
    /* Create thread to monitor events from wpa supplicant */
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, 256*1024);
    
    ret = pthread_create(&monitor_thread, &thread_attr, monitor_thread_task, NULL);
    
    
    if (ret != 0) {        
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Monitor thread creation failed \n");
        return RETURN_ERR;
    }
    // Start wpa_supplicant health monitor thread
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Starting wpa_supplicant health monitor thread \n");
    ret = pthread_create(&wpa_health_mon_thread, NULL, monitor_wpa_health, NULL);
    if (ret != 0) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: WPA health monitor thread creation failed  \n");
        return RETURN_ERR;
    }
#ifdef WIFI_CLIENT_ROAMING
    // Initialize and set Roaming config params
    initialize_roaming_config();
#endif

    init_done=true;

    return RETURN_OK;
    
}

// Uninitializes wifi
INT wifi_uninit() {

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Stopping monitor thread\n");

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Disconnecting from the network\n");
    
    //check if "init_done" is not true (if previous init is not successful)
    //This helps to find if "wpa_health_mon_thread" created with a "pthread_create" during init or not.
    if(init_done == false) {
       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Previous wifi init is not successful\n");
       return RETURN_OK;
    }


    wpaCtrlSendCmd("DISCONNECT");
    wpaCtrlSendCmd("DISABLE_NETWORK 0");

    // adding a small sleep just to receive WPA_EVENT_DISCONNECTED
    // so that netsrvmgr can log a disconnected telemetry event
    sleep (1);

    if ((wpa_health_mon_thread) && ( pthread_cancel(wpa_health_mon_thread) == -1 )) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR, "[%s:%d] wpa health monitor thread cancel failed! \n",__FUNCTION__, __LINE__);
    }

    stop_monitor = true;
    pthread_join (wpa_health_mon_thread, NULL);
    pthread_join (monitor_thread, NULL);

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Stopping wpa_supplicant service\n");
#ifndef RDKC
    system("systemctl stop wpa_supplicant");
#else
    system("/etc/init.d/wpa_supplicant.service stop");
#endif    
    init_done=false;
    return RETURN_OK;
}

//clears internal variables to implement a factory reset of the Wi-Fi subsystem
INT wifi_factoryReset() {

    return RETURN_OK;
}

//Restore all radio parameters without touch access point parameters
INT wifi_factoryResetRadios() {
    return RETURN_OK;
}

//Restore selected radio parameters without touch access point parameters
INT wifi_factoryResetRadio(int radioIndex) {

    return RETURN_OK;
}

// resets the wifi subsystem, deletes all APs
INT wifi_reset() {
    return RETURN_OK;
}


// turns off transmit power for the entire Wifi subsystem, for all radios
INT wifi_down() {

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Bring the wlan interface down\n");
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Hardcoding the interface to wlan0 for now\n");
    system("ifconfig wlan0 down");
    return RETURN_OK;
}

INT parse_scan_results(char *buf, size_t len)
{
    uint32_t count = 0;
    char tmp_str[100];
    char flags[256];
    char *delim_ptr, *ptr, *encrypt_ptr,*security_ptr;
    int i;
    if ((len == 0) || (buf == NULL)) return count;

    /* example output:
        * bssid / frequency / signal level / flags / ssid
        * b8:62:1f:e5:dd:5b       5200    -55     [WPA2-EAP-CCMP][ESS]    BCLMT-Wifi
        */

    /* skip heading */
    ptr = strstr(buf,"/ ssid");
    if (ptr == NULL) return count;
    ptr += strlen("/ ssid") + 1;

    // Memset ap_list before filling the list
    memset(&ap_list,0,sizeof(ap_list));

    /* Parse scan results */
    while ((delim_ptr=strchr(ptr, '\t')) != NULL) {

        /* Parse bssid */
        memcpy(ap_list[count].ap_BSSID, ptr, (delim_ptr-ptr));
        ap_list[count].ap_BSSID[delim_ptr-ptr] = '\0';
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"bssid=%s \n",ap_list[count].ap_BSSID); */
     
        /* Parse frequency band  */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        if(ptr) {
           char freq[10];
           strncpy(freq,ptr,10);
           int frequency=strtol(freq,NULL,10);
           ((frequency/1000) == 2)?strcpy(ap_list[count].ap_OperatingFrequencyBand,"2.4GHz"):strcpy(ap_list[count].ap_OperatingFrequencyBand,"5GHz");
        }
        //memcpy(ap_list[count].ap_OperatingFrequencyBand, ptr, (delim_ptr-ptr));
        //ap_list[count].ap_OperatingFrequencyBand[delim_ptr-ptr] = '\0';
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"freq=%s \n",ap_list[count].ap_OperatingFrequencyBand); */

        /* parse signal level */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(tmp_str, ptr, (delim_ptr-ptr));
        tmp_str[delim_ptr-ptr] = '\0';
        ap_list[count].ap_SignalStrength = atoi(tmp_str);
/*        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"signal strength=%d \n",ap_list[count].ap_SignalStrength); */

        /* parse flags */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(flags, ptr, (delim_ptr-ptr));
        flags[delim_ptr-ptr] = '\0';
        memset(ap_list[count].ap_SecurityModeEnabled, 0, sizeof(ap_list[count].ap_SecurityModeEnabled));
        memset(ap_list[count].ap_EncryptionMode, 0, sizeof(ap_list[count].ap_EncryptionMode));
        encrypt_ptr=ap_list[count].ap_EncryptionMode;
        security_ptr=ap_list[count].ap_SecurityModeEnabled;
        int len = sizeof(wifi_securityModes)/sizeof(wifi_securityModes[0]);
        for(i = 0; i < len; i++)
        {
            if(NULL != strcasestr(flags,wifi_securityModes[i].apSecurityEncryptionString)) {
                strcpy(security_ptr, wifi_securityModes[i].modeString);
                strcpy(encrypt_ptr, wifi_securityModes[i].encryptionString);
                break;
            }
        }
        if (encrypt_ptr > ap_list[count].ap_EncryptionMode) {
            *(encrypt_ptr-1)='\0';
        }
        if (security_ptr > ap_list[count].ap_SecurityModeEnabled) {
            *(security_ptr-1)='\0';
        }

        /* parse SSID */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\n');
        *delim_ptr = '\0'; // alters the buffer passed in; put back the '\n' after printf_decode, if this is a problem
        printf_decode (ap_list[count].ap_SSID, 64, ptr);
        RDK_LOG (RDK_LOG_DEBUG, LOG_NMGR,
                "decoded SSID=%s (encoded SSID=%s) flags=%s SecuritymodeEnabled=%s EncryptionMode=%s\n",
                ap_list[count].ap_SSID, ptr, flags, ap_list[count].ap_SecurityModeEnabled, ap_list[count].ap_EncryptionMode);
        // *delim_ptr='\n'; // put back the '\n' after printf_decode

        ptr = delim_ptr + 1;
        // increment ap_count only if bssid is filled properly
        if(ap_list[count].ap_BSSID[0] != '\0')
            count++;
    }

    return count;
}

INT wifi_getNeighboringWiFiDiagnosticResult(INT radioIndex, wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size) 
{
    size_t return_len=sizeof(return_buf)-1;
    int retry = 0;
    
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Starting a single scan..\n");
    pthread_mutex_lock(&wpa_sup_lock);
    if (cur_scan_state == WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan is already in progress, Waiting for the scan results. \n");
    } else {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: No in progress scanning, Starting a fresh scan.\n");
        bNoAutoScan=TRUE;
        wpaCtrlSendCmd("BSS_FLUSH 0");
        wpaCtrlSendCmd("SCAN");
        if (strstr(return_buf, "FAIL-BUSY") != NULL) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Scan command returned %s .. waiting \n", return_buf);            
            wpaCtrlSendCmd("BSS_FLUSH 0");
            sleep(1); 
            wpaCtrlSendCmd("SCAN");
            if (strstr(return_buf, "FAIL-BUSY") != NULL) {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Scan command returned %s FAILED \n", return_buf);
                goto exit_err;
            }
        }
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan command returned %s \n", return_buf);
        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    while ((cur_scan_state !=  WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) &&(retry++ < 1000)) {
        usleep(WPA_SUP_TIMEOUT);
    }
    pthread_mutex_lock(&wpa_sup_lock);    
    if (cur_scan_state != WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) { 
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Scan timed out retry times = %d \n",retry);
        //*output_array_size=0;
       // goto exit_err;
    } //else {
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Trying to read Scan results \n"); // Lets read scan_results even if it is timed out FIX:- Xi-6 Scan timeout
    wpaCtrlSendCmd("SCAN_RESULTS");
    ap_count = parse_scan_results(return_buf, return_len);
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Scan results contains %d BSSIDs. \n",ap_count);
    if (ap_count > 0) {
        int i;            
        *output_array_size = ap_count;
        *neighbor_ap_array = (wifi_neighbor_ap_t *)malloc(ap_count*sizeof(wifi_neighbor_ap_t));
            
        if(*neighbor_ap_array == NULL) {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Malloc Memory allocation failure\n");            
            goto exit_err;
        }
        for (i=0; i<*output_array_size; i++)
            (*neighbor_ap_array)[i] = ap_list[i];
    }        
   // }
   cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
   bNoAutoScan=FALSE;
   pthread_mutex_unlock(&wpa_sup_lock);
   return RETURN_OK;

 exit_err:   
   cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE;
   bNoAutoScan=FALSE;
   pthread_mutex_unlock(&wpa_sup_lock);
   return RETURN_ERR; 
}

INT wifi_getSpecificSSIDInfo(const char* SSID, WIFI_HAL_FREQ_BAND band, wifi_neighbor_ap_t **filtered_ap_array, UINT *output_array_size)   // ssid, band , output_array
{
    char freq_list_string[BUF_SIZE];
    char cmd[BUF_SIZE];
    wifi_neighbor_ap_t filtered_APList[32];
    int bssCount = 0;
    int ret = RETURN_ERR;
    memset(&freq_list_string,0,BUF_SIZE);
    memset(&cmd,0,BUF_SIZE);
    if(band != WIFI_HAL_FREQ_BAN_NONE)
    {
        if( RETURN_OK == getFrequencyListFor_Band(band,freq_list_string) && freq_list_string != NULL)
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Setting scan Freq based on selected Band to - %s \n",freq_list_string);
            snprintf(cmd,BUF_SIZE,"SET freq_list %s",freq_list_string);
            pthread_mutex_lock(&wpa_sup_lock);
            wpaCtrlSendCmd(cmd);   //wpa_cli freq_list + bands returned from the above static function parsed results
            pthread_mutex_unlock(&wpa_sup_lock);
        }
        else
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Error in getting the Frequency list for specified Band, NOT SCANNING . \n");
            return RETURN_ERR;
        }
    }

    int timeout = 8;
    bssCount = get_wifi_self_steer_matching_bss_list(SSID,filtered_APList,timeout);  //setting time limit as 8 (to make scan complete)
    *output_array_size = bssCount;
    if(bssCount == 0)
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: No BSS found with given band and frequency \n");
        ret = RETURN_ERR;
    }
    else
    {
        RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"WIFI_HAL: Found %d  BSS ids' for SSID %s \n",bssCount,SSID);
        *filtered_ap_array = (wifi_neighbor_ap_t *)malloc(bssCount*sizeof(wifi_neighbor_ap_t));
        if(*filtered_ap_array == NULL)
        {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Memory allocation failure\n");
            ret = RETURN_ERR;
        }
        else
        {
            int i;
            for (i=0; i<*output_array_size; i++)
                (*filtered_ap_array)[i] = filtered_APList[i];
            ret = RETURN_OK;
        }
    }
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("SET freq_list 0");   //reset the freq_list wpa_cli freq_list 0
    pthread_mutex_unlock(&wpa_sup_lock);
    return ret;
}

/**************WiFi Diagnostics********************/

INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string) {

    int retStatus = RETURN_ERR;
    if(!output_string) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in getting supported bands.. Null string\n");
        return RETURN_ERR;
    }
    // Check if the client is Dual band supported
    if(isDualBandSupported() == true) {
        snprintf(output_string, 64, "2.4GHz,5GHz");
    } else {
        // Get Supported Modes and decide band based on that
        pthread_mutex_lock(&wpa_sup_lock);
        retStatus = wpaCtrlSendCmd("GET_CAPABILITY channels");
        if(retStatus == RETURN_OK) {
            if(strstr(return_buf,"Mode[A]") != NULL) {
                snprintf(output_string, 64, "5GHz");
            } else if(strstr(return_buf,"Mode[B]") != NULL || strstr(return_buf,"Mode[G]") != NULL) {
                snprintf(output_string, 64, "2.4GHz");
            } else {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in getting supported bands- Unable to get Freq Modes\n");
            }
        } else {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in getting supported bands- Unable to Channel Capability\n");
        }
        pthread_mutex_unlock(&wpa_sup_lock);
    }
    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR,"[%s:%d] SupportedFrequencyBands - %s\n",__FUNCTION__,__LINE__,output_string);
    return RETURN_OK;
}

INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) {

    int retStatus = RETURN_OK;
    CHAR frequency_string[8] = "";
    int frequency = 0;

    if(!output_string) {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in getting supported bands.. Null string\n");
        return RETURN_ERR;
    }
    if (RETURN_OK == wifi_getRadioSignalParameter ("FREQUENCY", frequency_string) &&
            1 == sscanf (frequency_string, "%d", &frequency) &&
            0 != frequency ) {
        int band = frequency/1000;
        if(band == 5) {
            snprintf(output_string, 64, "5GHz");
        } else if (band == 2) {
            snprintf(output_string, 64, "2.4GHz");
        } else {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"[%s:%d] Failure in getting OperatingFrequencyBand \n",__FUNCTION__,__LINE__);
            retStatus = RETURN_ERR;
        }
    } else {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"[%s:%d] Failure in getting OperatingFrequencyBand - Failed to get Frequency\n",__FUNCTION__,__LINE__);
        retStatus = RETURN_ERR;
    }
    return retStatus;
}

INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) {
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"a,n,ac");
    return RETURN_OK;
}

INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly) {

    CHAR frequency_string[8] = "";
    int frequency = 0;
    int ret = RETURN_ERR;
    int freqBand = 0;

    if(!output_string) {
        return RETURN_ERR;
    }
    if (RETURN_OK == wifi_getRadioSignalParameter ("FREQUENCY", frequency_string) &&
            1 == sscanf (frequency_string, "%d", &frequency) &&
            0 != frequency)
    {
        freqBand = frequency/1000;
        if(freqBand == 2 && radioIndex == 0) {
            snprintf(output_string, 64,"b,g,n");
            ret = RETURN_OK;
        } else if(freqBand == 5 && radioIndex == 1) {
             snprintf(output_string, 64,"a,n,ac");
             ret = RETURN_OK;
        } else {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Invalid frequency band, Failure in getting Operating standard.\n");
        }
    }
    if(gOnly != NULL) *gOnly = false;
    if(nOnly != NULL) *nOnly = false;
    if(acOnly != NULL) *acOnly = false;
    return ret;
}

static void getPossibleChannelsFromCapability(char* channelCap,char *modeStr,char* output_string)
{
    char *pch=NULL,*final=NULL;
    pch = strtok(channelCap,"\n");
    while (pch != NULL)
    {   
        if(strstr(pch,modeStr))
        {
            pch=strchr(pch,':');
            pch=pch+2;
            final = pch;
            while(*final != '\0')
            {
                if(*final == ' ')
                {
                    *final= ',';
                }
                final++;
            }
            break;
        }
        pch = strtok (NULL, "\n");
    }
    if(pch !=NULL)
        strcpy(output_string,pch);
}

INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string) {

    int ret;
    char tmp_buff[BUFF_LEN_1024];
    if(!output_string) {
        return RETURN_ERR;
    }
    memset(tmp_buff,0,BUFF_LEN_1024);
    pthread_mutex_lock (&wpa_sup_lock);
    ret = wpaCtrlSendCmd ("GET_CAPABILITY channels");
    if(ret == RETURN_OK)
    {
       strncpy(tmp_buff,return_buf,BUFF_LEN_1024);
       pthread_mutex_unlock (&wpa_sup_lock);
    }
    else 
    {
       RDK_LOG( RDK_LOG_ERROR,LOG_NMGR,"Error in getting channel capability.\n");
       pthread_mutex_unlock (&wpa_sup_lock);
       return RETURN_ERR;
    }
    if(radioIndex == 1)
    {
        getPossibleChannelsFromCapability(tmp_buff,"Mode[A]",output_string);
    }
    else
    {
        getPossibleChannelsFromCapability(tmp_buff,"Mode[G]",output_string);
    }
    return RETURN_OK;
}

INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) {

    char resultBuff[64];
    char cmd[64];
    char interfaceName[10];
    int  bandWidth = 0;
    FILE *fp = NULL;
    int ret = RETURN_ERR;
    bool iw_info_failed=false;
    char*  bandwidth_string=NULL;
    char*  bandwidth_token=NULL;
    bool bandwidth_found=false;

    if(!output_string) {
        return ret;
    }

    memset(interfaceName,0,sizeof(interfaceName));
    memset(cmd,0,sizeof(cmd));
    memset(resultBuff,0,sizeof(resultBuff));

    wifi_getRadioIfName(radioIndex, interfaceName);
    if(interfaceName[0] == '\0')
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Unable to get wireless interface name, Get bandwidth failed \n");
        return ret;
    }
    snprintf(cmd,sizeof(cmd),"iw dev %s info | grep channel | cut -f 2 -d ','",interfaceName);
    fp = popen(cmd,"r");
    if (fp != NULL)
    {
        if ((fgets(resultBuff, sizeof (resultBuff), fp) != NULL) && (resultBuff[0] != '\0'))
        {
            sscanf(resultBuff,"%*s%d%*s",&bandWidth);    /* Expected output :-  " width: 80 MHz" */
            if(bandWidth != 0) {
                snprintf(output_string, 64, "%dMHz",bandWidth);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: OperatingChannelBandwidth =  %s\n",output_string);
                ret = RETURN_OK;
            } else {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in getting bandwidth \n");
            }
        }
        else
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Unable to read Channel width from iw \n");
            iw_info_failed=true;
        }
        pclose(fp);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: popen() failed. failure in getting Channel Bandwidth\n");
        iw_info_failed=true;
    }

    if(true == iw_info_failed) //iw info fallback
    {
       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: iw info command failed, fall back to iw link command\n");
       
       memset(cmd,0,sizeof(cmd));
       memset(resultBuff,0,sizeof(resultBuff));

       snprintf(cmd,sizeof(cmd),"iw dev %s link | grep tx",interfaceName);
       fp = popen(cmd,"r");
       if (fp != NULL)
       {
           if ((fgets(resultBuff, sizeof (resultBuff), fp) != NULL) && (resultBuff[0] != '\0'))
           {
               char* resultBuff_P=resultBuff;         
               while ((bandwidth_string = strtok_r(resultBuff_P, " ", &resultBuff_P)))
               {
                   bandwidth_token = strstr(bandwidth_string, "MHz");
                   if(NULL != bandwidth_token )
                   {   
                       strcpy(output_string,bandwidth_string); //copy bandwidth string to o/p string
                       bandwidth_found=true;
                       break;
                   }
               }
               if (true == bandwidth_found)
	       {
                   RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: OperatingChannelBandwidth =  %s\n",output_string);
                   ret = RETURN_OK;   
	       }
	       else
               {
                    RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL:MHz information missing in iw link o/p \n");
               }
           }
           else
           {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in getting bandwidth \n");
           }				
       }
       else
       {
          RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: popen() failed. failure in getting Channel Bandwidth\n");
       }

    }
    return ret;
}

INT wifi_getSSIDName(INT apIndex, CHAR *output_string) {
    
    int ret = RETURN_ERR;
    if (output_string != NULL)
    {
        pthread_mutex_lock(&wpa_sup_lock);
        wpaCtrlSendCmd("STATUS");
        char *ssid = getValue(return_buf, "\nssid"); // include '\n' to avoid a match with "bssid"
        if (ssid == NULL)
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR, "%s: ssid not found in STATUS output\n", __FUNCTION__);
        }
        else
        {
            // TODO: assumes 'output_string' is at least MAX_SSID_LEN+1 big. wifi_getSSIDName needs 'max_len' 3rd arg to avoid assumption.
            printf_decode (output_string, MAX_SSID_LEN+1, ssid);
            ret = RETURN_OK;
        }
        pthread_mutex_unlock(&wpa_sup_lock);
    }
    return ret;
}

INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string) {

    return RETURN_OK;
}

INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string) {

    char *bssid = NULL;
    int maxBssidLen = 18;

    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("STATUS");
    bssid = getValue(return_buf, "bssid");
    if (bssid == NULL)
        goto exit_err;
    else
        if (output_string != NULL) strncpy(output_string, bssid,maxBssidLen);

    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;


exit_err:
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_ERR;
}

INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) {
    
    char *ptr, *bssid;
    
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("STATUS");
    bssid = getValue(return_buf, "bssid");
    if (bssid == NULL) 
        goto exit_err;
    else
        if (output_string != NULL) strcpy(output_string, bssid);
            
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;
            
        
exit_err:
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_ERR;
}

static INT wifi_getRadioSignalParameter (const CHAR* parameter, CHAR *output_string) {

    if (!parameter || !output_string) {
        return RETURN_ERR;
    }

    char *parameter_value= NULL;
    int ret = RETURN_ERR;

    pthread_mutex_lock (&wpa_sup_lock);
    wpaCtrlSendCmd ("SIGNAL_POLL");
    if (NULL != (parameter_value = getValue(return_buf, parameter)))
    {
        strcpy (output_string, parameter_value);
        ret = RETURN_OK;
    }
    pthread_mutex_unlock (&wpa_sup_lock);

    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR, "[%s] return code = [%d], parameter = [%s], parameter_value = [%s]\n",
            __FUNCTION__, ret, parameter, parameter_value ? parameter_value : "NULL");
    return ret;
}

static int wifi_getRadioChannelFromFrequency(int frequency)
{
    if (frequency == 2484)
        return 14;
    else if (frequency < 2484)
        return (frequency - 2407) / 5;
    else if (frequency >= 4910 && frequency <= 4980)
        return (frequency - 4000) / 5;
    else if (frequency <= 45000)
        return (frequency - 5000) / 5;
    else if (frequency >= 58320 && frequency <= 64800)
        return (frequency - 56160) / 2160;
    else
        return 0;
}
// Ping to wpa_supplicant and get connection Status, Ret = 0-> success, -1-> Response failure ,-2-> Command failure
static int wifi_getWpaSupplicantStatus()
{
    int retStatus = -1;
    char temp_buff[50];
    int pingStatus = -1;

    memset(temp_buff,0,sizeof(temp_buff));
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("PING");
    strncpy(temp_buff,return_buf,sizeof(temp_buff)-1);
    pthread_mutex_unlock(&wpa_sup_lock);

    if(temp_buff[0] != '\0' && retStatus == 0 )
    {
        if(strncmp(temp_buff,"PONG",4) == 0)
        {
            pingStatus = 0;
        }
        else
        {
            pingStatus = -1; // Response failure
        }
    }
    else
    {
        pingStatus = -2; // Command Failure
    }
    return pingStatus;
}

// Open wpa_supplicant Control and Monitor Connection, Ret = 0-> Success , -1 -> failure
static int wifi_openWpaSupConnection()
{
    int retStatus = -1;

    // Open Control connection
    pthread_mutex_lock(&wpa_sup_lock);
    wpa_ctrl_close(g_wpa_ctrl);
    g_wpa_ctrl = wpa_ctrl_open(WPA_SUP_CTRL);
    if(NULL != g_wpa_ctrl) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant control connection opened successfuly. \n");
    } else{
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in opening wpa_supplicant control connection.\n");
        pthread_mutex_unlock(&wpa_sup_lock);
        return retStatus;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    
    // Open Monitor Connection
    pthread_mutex_lock(&wpa_sup_lock);
    wpa_ctrl_close(g_wpa_monitor);
    g_wpa_monitor = wpa_ctrl_open(WPA_SUP_CTRL);
    if(NULL != g_wpa_monitor) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant monitor connection opened successfuly. \n");
        if ( wpa_ctrl_attach(g_wpa_monitor) != 0) {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpa_ctrl_attach failed \n");
        } else {
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Monitor connection Attached Successfully. \n");
            retStatus = 0;
        }
    } else{
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Failure in opening wpa_supplicant monitor connection.\n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return retStatus;
}
void monitor_wpa_health()
{
    int retStatus = -1;
    int printInterval = 0;
    int pingCount = 0;
    int openStatus = -1;
    int pingRecoveryCount = 0;

    while(true)
    {
        retStatus = wifi_getWpaSupplicantStatus();
        if(retStatus == 0)
        {
            if(printInterval >= 4)
            {
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat success. \n");
                printInterval = 0;
            }
            else
                printInterval++;
        }
        else
        { 
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat failed, Reason: %s \n",retStatus==-1?"No response.":"Command failure.");
            pingCount = 0;
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Trying for 5 continues pings...\n");
            while(pingCount < 5)
            {
                retStatus = wifi_getWpaSupplicantStatus();
                if(!retStatus) {
                    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat success. , Breaking Ping attempts\n");
                    // If the connection is alternatively failing for 3 times, Then it seems like an inconsistent connection, Lets reopen a new control connection. 
                    if(pingRecoveryCount >= 2) {
                        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat - inconsistent control connection: Reopen new one.\n");
                        wifi_openWpaSupConnection();
                        pingRecoveryCount = 0;
                    } else {
                        pingRecoveryCount++;
                    }
                    break; // Got one Success lets break
                }
                else
                    RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: wpa_supplicant heartbeat failed, Reason: %s, Attempt = %d\n",retStatus==-1?"No response.":"Command failure.",pingCount+1);
                pingCount++;
                sleep(3);
            }
            if(pingCount >= 5) {
                 RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Heartbeat failed for all attempts, Trying to reopen Connection.\n");
                 wifi_openWpaSupConnection();
            }
        }
        sleep(WPA_SUP_PING_INTERVAL);
    }
}

INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong) {

    if(!output_ulong) {
        return RETURN_ERR;
    }

    CHAR frequency_string[8] = "";
    int frequency = 0;
    int channel = 0;
    int ret = RETURN_ERR;
    if (RETURN_OK == wifi_getRadioSignalParameter ("FREQUENCY", frequency_string) &&
            1 == sscanf (frequency_string, "%d", &frequency) &&
            0 != frequency &&
            0 != (channel = wifi_getRadioChannelFromFrequency (frequency)))
    {
        *output_ulong = channel;
        ret = RETURN_OK;
    }

    RDK_LOG( RDK_LOG_DEBUG, LOG_NMGR, "[%s] return code = [%d], Channel Spec: %lu\n", __FUNCTION__, ret, *output_ulong);
    return ret;
}

INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string) {
    if (!output_string)
        return RETURN_ERR;
    snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
    return RETURN_OK;
}

INT wifi_getSSIDNumberOfEntries(ULONG *output) {

    if(!output) {
        return RETURN_ERR;
    }

    *output = 1;
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: SSID entries:1\n");
    return RETURN_OK;

}

INT wifi_getRadioTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct) {

    FILE *fp = NULL;
    char resultBuff[BUF_SIZE];
    char cmd[50];
    char interfaceName[10];
    long long int rx_bytes = 0,rx_packets = 0,rx_err = 0,rx_drop = 0;
    long long int tx_bytes = 0,tx_packets = 0,tx_err = 0,tx_drop = 0;
    int numParams = 0;
    int noise = 0;
    char* ptr = NULL;

    if(!output_struct) {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"output struct is null");
        return 0;
    }

    // memset arrays
    memset(resultBuff,0,sizeof(resultBuff));
    memset(cmd,0,sizeof(cmd));
    memset(interfaceName,0,sizeof(interfaceName));

    wifi_getRadioIfName(0,interfaceName);
    snprintf(cmd,sizeof(cmd),"cat /proc/net/dev | grep %s",interfaceName);
    fp = popen(cmd,"r");
    if (fp != NULL)
    {
        if (fgets(resultBuff, sizeof (resultBuff), fp) != NULL)
        {
            numParams = sscanf( resultBuff," %[^:]: %lld %lld %lld %lld %*u %*u %*u %*u %lld %lld %lld %lld %*u %*u %*u %*u",interfaceName, &rx_bytes, &rx_packets,&rx_err,&rx_drop,&tx_bytes,&tx_packets,&tx_err,&tx_drop );
            if(numParams != 9)
            {
                RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in parsing Radio Stats params \n");
            }
            output_struct->radio_PacketsSent = tx_packets;
            output_struct->radio_PacketsReceived = rx_packets;
            output_struct->radio_BytesSent = tx_bytes;
            output_struct->radio_BytesReceived = rx_bytes;
            output_struct->radio_ErrorsReceived = rx_err;
            output_struct->radio_ErrorsSent = tx_err;
            output_struct->radio_DiscardPacketsSent = tx_drop;
            output_struct->radio_DiscardPacketsReceived = rx_drop;
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"[tx_packets = %lld] [rx_packets =  %lld] [tx_bytes = %lld] [rx_bytes = %lld] [rx_err = %lld] [tx_err = %lld] [tx_drop = %lld] [rx_drop = %lld] \n",tx_packets,rx_packets,tx_bytes,rx_bytes,rx_err,tx_err,tx_drop,rx_drop);
        }
        else
        {
            RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in reading /proc/net/dev file \n");
        }
        pclose(fp);
    }
    else
    {
        RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in popen() : Opening /proc/net/dev failed \n");
    }
    pthread_mutex_lock(&wpa_sup_lock);
    wpaCtrlSendCmd("SIGNAL_POLL");
    ptr = getValue(return_buf, "NOISE");
    if(NULL != ptr)
    {
        noise = atoi(ptr);
        output_struct->radio_NoiseFloor = noise;
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n noise = %d ",noise);
    }
    else
    {
        RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Noise is not available in siganl poll \n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;
}

INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool) {
    *output_bool = (g_wpa_monitor != NULL);
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The radio is %s\n", g_wpa_monitor ? "enabled" : "not enabled");
    return RETURN_OK;
}

INT wifi_getRadioStatus(INT radioIndex, CHAR *output_string) {
    int ret = RETURN_ERR;
    FILE *fp = NULL;
    char resultBuff[BUF_SIZE];
    char cmd[50];
    char radio_status[20];
    char cli_buff[512];
    char *ptr = NULL;

    if(!output_string){
       RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"WIFI_HAL: Output_string is null\n");
       return ret;
    }

    pthread_mutex_lock(&wpa_sup_lock);
    int status = wpaCtrlSendCmd("STATUS");
    strncpy(cli_buff,return_buf,512);
    pthread_mutex_unlock(&wpa_sup_lock);
    memset(radio_status,0,sizeof(radio_status));
    if (status == 0)
    {
        ptr = getValue(cli_buff, "wpa_state");
        if(NULL != ptr)
        {
            strcpy(radio_status,ptr);
            if(strcmp(radio_status,"INTERFACE_DISABLED") == 0)
            {
                strcpy(output_string,"DOWN");
            }
            else
            {
                strcpy(output_string,"UP");
            }
            ret = RETURN_OK;
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n WPA State : %s, Radio State :%s ",radio_status,output_string);
        }
        else
        {
            ret = RETURN_ERR;
            RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Radio State is not available in wpa_cli STATUS \n");
        }
    }
    else      // alternate method for getting wlan0 status
    {
       memset(cmd,0,sizeof(cmd));
       memset(resultBuff,0,sizeof(resultBuff));
       snprintf(cmd,sizeof(cmd),"cat /sys/class/net/wlan0/operstate");
       fp = popen(cmd,"r");
       if (fp != NULL)
       {
          if (fgets(resultBuff, sizeof (resultBuff), fp) != NULL)
          {
             sscanf(resultBuff,"%s",radio_status);
             if ( strcmp(radio_status,"up") == 0)
                strcpy(output_string, "UP");
             else if (strcmp(radio_status,"down") == 0)
                strcpy(output_string, "DOWN");
             RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The radio is %s \n",output_string);
             ret = RETURN_OK;
          }
          else
          {
             RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in executing `cat /sys/class/net/wlan0/operstate`  parsing \n");
             ret = RETURN_ERR;
          }
          pclose(fp);
       }
       else
       {
          RDK_LOG( RDK_LOG_ERROR, LOG_NMGR,"Error in popen() of sys/class/net/wlan0/operstate : %s \n",__FUNCTION__);
          ret=RETURN_ERR;
       }
    }
    return ret;
}

INT wifi_getRegulatoryDomain(INT radioIndex, CHAR* output_string){
    int ret = RETURN_ERR;
    if(!output_string){
       RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: Output_string is null\n");
       return ret;
    }
    pthread_mutex_lock(&wpa_sup_lock);
    int status = wpaCtrlSendCmd("GET COUNTRY");

    if(status == 0 && return_buf[0] != '\0'){
       snprintf(output_string, 4, "%s", return_buf);
       ret = RETURN_OK;
    }
    else{
        ret = RETURN_ERR;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return ret;
}

INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) {
    
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: MaxBitRate information will be implemented\n");
    return RETURN_ERR;
}

INT wifi_getRadioMCS(INT radioIndex, INT *output_INT){
    
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"WIFI_HAL: MCS could not be determined\n");
    return RETURN_ERR;
}

INT wifi_getSSIDTrafficStats(INT ssidIndex, wifi_ssidTrafficStats_t *output_struct) {

char filename[]="/tmp/wlparam.txt";
char *bufPtr=NULL;
char *ptrToken;   

    if(!output_struct) {
      RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"output struct is null");
      return 0;
    }
    system("wl counter > /tmp/wlparam.txt");
    bufPtr=readFile(filename);
    if(bufPtr)
    {
        ptrToken = strtok (bufPtr," \t\n");
        while (ptrToken != NULL)
        {
            if (strcmp(ptrToken, "txdatamcast") == 0)
            {
                ptrToken = strtok (NULL, " \t\n");
                output_struct->ssid_MulticastPacketsSent=strtoull(ptrToken, NULL, 10);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n txdatamcast = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else if (strcmp(ptrToken, "txdatabcast") == 0)
            {
                ptrToken = strtok (NULL, " \t\n");
                output_struct->ssid_BroadcastPacketsSent=strtoull(ptrToken, NULL, 10);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n txdatabcast = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else if (strcmp(ptrToken, "txnoack") == 0)
            {
                ptrToken = strtok (NULL, " \t\n");
                output_struct->ssid_ACKFailureCount=strtoull(ptrToken, NULL, 10);
                RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"\n txnoack  = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else
            {
                ptrToken = strtok (NULL, " \t\n");
            }   
        }   
        free(bufPtr);
    }

    //TODO: Get the following stats in. Commenting it out to unblock basic testing
    /*NETAPP_WIFI_STATS tTestInfo;
    memset(&tTestInfo, 0, sizeof(tTestInfo));
    NetAppWiFiTestGetStats(hNetApp, &tTestInfo);
    output_struct->ssid_MulticastPacketsSent = tTestInfo.txdatamcast;
    output_struct->ssid_BroadcastPacketsSent = tTestInfo.txdatabcast;
    output_struct->ssid_ACKFailureCount = tTestInfo.txnoack;*/
    return RETURN_OK;
}

INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) {

    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"Extension channel is Auto\n");
    strcpy(output_string, "Auto");
    return RETURN_OK;
}

/***************Stubbed out functions**********************/
INT wifi_getRadioNumberOfEntries(ULONG *output) {
    RDK_LOG( RDK_LOG_INFO, LOG_NMGR,"The radio number of entries is always 1\n");
    *output = 1;
    return RETURN_OK;
}

INT wifi_setRadioEnable(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) {
    strcpy(output_string, "wlan0");
    return RETURN_OK;
}
INT wifi_setRadioScanningFreqList(INT radioIndex, const CHAR *freqList)
{
   int result = RETURN_OK;
   char cmd[BUF_SIZE];

   memset(cmd,0,BUF_SIZE);
   snprintf(cmd,BUF_SIZE,"SET freq_list %s",freqList);
   pthread_mutex_lock(&wpa_sup_lock);
   if(wpaCtrlSendCmd(cmd) != RETURN_OK)
   {
      result = RETURN_ERR;
   }
   pthread_mutex_unlock(&wpa_sup_lock);
   return result;
}
INT wifi_getDualBandSupport()
{
   if(isDualBandSupported() == true)
      return 1;
   else 
      return 0;
}


INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag) {
    return RETURN_OK;
}

INT wifi_setRadioChannel(INT radioIndex, ULONG channel) {
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool) {
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool) {
    return RETURN_OK;
}

INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) {
    return RETURN_OK;
}

INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds) {
    return RETURN_OK;
}

INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) {
    return RETURN_OK;
}

INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) {
    return RETURN_OK;
}

INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string) {
    return RETURN_OK;
}

INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string) {
    return RETURN_OK;
}

INT wifi_setRadioMCS(INT radioIndex, INT MCS) {
    return RETURN_OK;
}

INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) {
    return RETURN_OK;
}

INT wifi_getRadioTransmitPower(INT radioIndex, INT *output_INT) {
    return RETURN_OK;
}

INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower) {
    return RETURN_OK;
}

INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported) {
    return RETURN_OK;
}

INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) {
    return RETURN_OK;
}

INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output) {
    return RETURN_OK;
}

INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output) {
    return RETURN_OK;
}
INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold) {
    return RETURN_OK;
}

INT wifi_getRadioChannelSwitchingCount(INT radioIndex, INT *output) {
    return RETURN_OK;
}

INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output) {
    return RETURN_OK;
}

INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod) {
    return RETURN_OK;
}

INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output) {
    return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates) {
    return RETURN_OK;
}

INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) {
    return RETURN_OK;
}

INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) {
    return RETURN_OK;
}

INT wifi_applyRadioSettings(INT radioIndex) {
    return RETURN_OK;
}

INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex) {
    return RETURN_OK;
}

INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) {
    return RETURN_OK;
}

INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) {
    return RETURN_OK;
}

INT wifi_applySSIDSettings(INT ssidIndex) {
    return RETURN_OK;
}


