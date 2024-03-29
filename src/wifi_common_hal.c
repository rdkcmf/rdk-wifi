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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <wifi_common_hal.h>
#include <stdbool.h>
#include <pthread.h>
#include <ifaddrs.h>

#include <sys/ioctl.h>
#include <netinet/in.h>

#include "wifi_log.h"

#define MAX_SSID_LEN        32           /* Maximum SSID name */
#define MAX_VERSION_LEN     16          /* Maximum Version Len */
#define BUFF_LEN_1024       1024
#define BUFF_LEN_64         64
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
    NET_WIFI_SECURITY_WPA_WPA2_PSK,
    NET_WIFI_SECURITY_WPA_WPA2_ENTERPRISE,
    NET_WIFI_SECURITY_WPA3_PSK_AES,
    NET_WIFI_SECURITY_WPA3_SAE,
    NET_WIFI_SECURITY_NOT_SUPPORTED = 99,
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
};
*/
/*
static struct _wifi_securityModes
{
    const char          *modeString;
    const char          *encryptionString;
    const char          *apSecurityEncryptionString;
} wifi_securityModes[] =
{
    { "WPA3","AES","[WPA2-SAE-CCMP]" },
    { "WPA3","AES","[WPA2-SAE-CCMP-preauth]" },
    { "WPA2-WPA3","AES","[WPA2-PSK+SAE-CCMP]" },
    { "WPA2-WPA3","AES","[WPA2-PSK+SAE-CCMP-preauth]" },
    { "WPA-WPA2","TKIP","[WPA-PSK-TKIP][WPA2-PSK-TKIP]"},
    { "WPA-WPA2","TKIP","[WPA-PSK-TKIP][WPA2-PSK-TKIP-preauth]"},
    { "WPA-WPA2","AES","[WPA-PSK-TKIP][WPA2-PSK-CCMP-preauth]"},
    { "WPA-WPA2","AES","[WPA-PSK-CCMP][WPA2-PSK-CCMP]"},
    { "WPA-WPA2","AES","[WPA-PSK-CCMP][WPA2-PSK-CCMP-preauth]"},
    { "WPA-WPA2","AES","[WPA-PSK-TKIP+CCMP][WPA2-PSK-CCMP-preauth]"},
    { "WPA-WPA2","TKIP,AES","[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP]"},
    { "WPA-WPA2","TKIP,AES","[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP-preauth]"},

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
    { "WPA2","TKIP","[WPA2-PSK-TKIP-preauth]"},
    { "WPA","AES","[WPA-PSK-CCMP]"},
    { "WPA2","AES","[WPA2-PSK-CCMP]"},
    { "WPA2","AES","[WPA2-PSK-CCMP-preauth]"},
    { "WPA","TKIP,AES","[WPA-PSK-CCMP+TKIP]"},
    { "WPA2","TKIP,AES","[WPA2-PSK-CCMP+TKIP]"},
    { "WPA2","TKIP,AES","[WPA2-PSK-CCMP+TKIP-preauth]"},
    { "WEP","","WEP"},
    { "WPA2","AES","[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]"},
    { "WPA2-Enterprise","AES","[WPA2-EAP+FT/EAP-CCMP][ESS]"},
    { "None","","None"},
};
*/
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

void wifi_usleep(useconds_t usec)
{
  // WIFI_LOG_INFO("wifi hal calling sleep:%uus\n", (uint32_t) usec);
  if (usec >= 1000000) {
    (void) sleep((unsigned int) (usec / 1000000));
  }
  else {
    (void) usleep(usec);
  }
}
 
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

#define WPA_SUP_TIMEOUT         7000   /* 7 msec */
#define WPA_SUP_PING_INTERVAL   60 /* 1 min */

typedef enum {
    WIFI_HAL_WPA_SUP_SCAN_STATE_IDLE,
    WIFI_HAL_WPA_SUP_SCAN_STATE_CMD_SENT,
    WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED,
    WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED,
} WIFI_HAL_WPA_SUP_SCAN_STATE;

char* getValue(const char *buf, const char *keyword);
int wpaCtrlSendCmd(char *cmd);
int get_wifi_self_steer_matching_bss_list(const char* ssid_to_find,wifi_neighbor_ap_t neighborAPList[],int timeout);
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
char cmd_buf[1024], return_buf[96*1024];
wifi_neighbor_ap_t ap_list[512];


static wifi_context_t g_ctx;
static void wifi_initContext(wifi_context_t * ctx, wifi_halConfig_t *conf);
static bool wifi_interfaceExists(const char * ifname);
bool wifi_interfaceIsWireless(const char * ifname);
static void wifi_interfaceSetEnabled(const char * ifname, bool enabled);

static char * wifi_readFile(const char * fname, bool sysfs);

pthread_t monitor_thread;
pthread_t wpa_health_mon_thread;
void* monitor_thread_task(void *param);
void* monitor_wpa_health(void* param);
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
            WIFI_LOG_ERROR("Failed generate HAL Version, ret = %d.\n",ret );
            retStatus = RETURN_ERR;
         }
    } else {
        WIFI_LOG_ERROR("Failed to get HAL Version - Input String is NULL.\n" );
        retStatus = RETURN_ERR;
    } 
    return retStatus;
}
static INT getFrequencyListFor_Band(WIFI_HAL_FREQ_BAND band, char *output_string)
{
    if(output_string == NULL)
    {
        WIFI_LOG_ERROR("[%s] Memory not allocated for output_string \n",__FUNCTION__);
        return RETURN_ERR;
    }
    char *s = NULL;
    char *t = NULL;
    char *r = NULL;
    char *saveptr = NULL;
    char lines[32][64];
    int i;
    INT ret = RETURN_ERR;

    WIFI_LOG_INFO("in getFrequencyListFor_Band ..\n");
    pthread_mutex_lock(&wpa_sup_lock);
    int ret_status = wpaCtrlSendCmd("GET_CAPABILITY freq");
    if(ret_status == RETURN_OK)
    {
        if( band == WIFI_HAL_FREQ_BAND_5GHZ)
        {
            s = strstr(return_buf, "Mode[A] Channels:");
            t = strstr(return_buf, "Mode[B] Channels:");
            if(t) *t = 0;
        }
        else if (band == WIFI_HAL_FREQ_BAND_24GHZ)
        {
            s = strstr(return_buf, "Mode[G] Channels:");
            t = strstr(return_buf, "Mode[A] Channels:");
            if(t) *t = 0;
        }
        if (s == NULL)
        {
            WIFI_LOG_INFO("[%s] Error in selecting the frequencies\n",__FUNCTION__);
            ret = RETURN_ERR;
        }
        else
        {
            s = s+18;
            r = strtok_r(s,"\n", &saveptr);
            i=0;
            while(r != NULL)
            {
                strcpy(lines[i],r);
                r = strtok_r(NULL,"\n", &saveptr);
                i++;
            }

            saveptr = NULL;
            for(int k=0;k<i;k++)
            {
                char *ptr = lines[k];
                strtok_r(ptr,"=", &ptr);
                char *tmp = strtok_r(ptr," ", &saveptr);
                strcpy(lines[k],tmp);
                strcat(output_string,lines[k]);
                strcat(output_string, " ");
            }
            WIFI_LOG_DEBUG("frequencies selected : [%s] \n",output_string);
            ret = RETURN_OK;
        }
    }
    else
    {
        WIFI_LOG_ERROR("[%s] Error in getting supported bands- Unable to get Channel Capability\n",__FUNCTION__);
        ret = RETURN_ERR;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return ret;
    //wpa_cli get_capability freq
}

char * wifi_readFile(const char * fname, bool sysfs)
{
    FILE    *fp = NULL;
    char    *buf = NULL;
    long    fBytes = 0;
    long    freadBytes = 0; 

    fp=fopen(fname,"r");
    if(fp==NULL)
    {
        WIFI_LOG_INFO("readFile(): File Open Error \n" );
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
            WIFI_LOG_INFO("readFile(): Memory Allocation Error \n" );
            fclose(fp);
            return NULL; 
        }
        freadBytes = fread(buf,sizeof(char),fBytes,fp);
        if (!sysfs && (freadBytes != fBytes)) // Do we need to proceed on partial read.. ? Blocking for now.
        {
            WIFI_LOG_ERROR(" readFile(): Error occured during fread(), freadBytes= %ld  \n" ,freadBytes); 
            fclose(fp);
            free(buf);
            return NULL;
        }
    }
    else
    {
       WIFI_LOG_ERROR("readFile(): File is empty \n" );
    }
    fclose(fp);
    return buf;
}

bool wifi_interfaceExists(const char * ifname)
{
    bool found = false;
    struct if_nameindex *ifp, *ifpsave;

    ifpsave = ifp = if_nameindex();

    if(!ifp){
        WIFI_LOG_DEBUG("if_nameindex call failed: %s\n", strerror(errno));
        return false;
    }
    while(ifp->if_index) {
        WIFI_LOG_DEBUG("comparing interface name '%s' with '%s' to check if exists\n",
          ifp->if_name, ifname);
        if (strcmp(ifp->if_name, ifname) == 0) {
            found = true;
            break;
        }
        ifp++;
    }
    if_freenameindex(ifpsave);
    return found;
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()
{
  return wifi_initWithConfig(NULL);
}

INT wifi_initWithConfig(wifi_halConfig_t *conf)
{
    int retry = 0;
    stop_monitor=false;
    pthread_attr_t thread_attr;
    int ret;

    wifi_initContext(&g_ctx, conf);

    WIFI_LOG_INFO("Initializing Generic WiFi hal.\n");
    if(init_done == true) {
       WIFI_LOG_INFO("Wifi init has already been done\n");
       return RETURN_OK;
    }

    WIFI_LOG_INFO("TELEMETRY_WIFI_WPA_SUPPLICANT:ENABLED \n");
    // Starting wpa_supplicant service if it is not already started
    WIFI_LOG_INFO("Starting wpa_supplicant service \n");

    #ifndef RDKC
    system("systemctl start wpa_supplicant");
    #else
    system("/etc/init.d/wpa_supplicant.service restart");
    #endif

   bool interfaceExists = wifi_interfaceExists(g_ctx.conf.wlan_Interface);
   if(interfaceExists)
   {

        /* Starting wpa_supplicant may take some time, try 75 times before giving up */
        retry = 0;    
        while (retry++ < 75) {
            WIFI_LOG_INFO("opening control path:%s\n", g_ctx.ctrl_path);
            g_wpa_ctrl = wpa_ctrl_open(g_ctx.ctrl_path);
            if (g_wpa_ctrl != NULL) break;
            WIFI_LOG_INFO("ctrl_open returned NULL \n");
            wifi_usleep(1000000);
        }

        if (g_wpa_ctrl == NULL) {
            WIFI_LOG_INFO("wpa_ctrl_open failed for control interface \n");
            return RETURN_ERR;
        }

        g_wpa_monitor = wpa_ctrl_open(g_ctx.ctrl_path);
        if ( g_wpa_monitor == NULL ) {
            WIFI_LOG_INFO("wpa_ctrl_open failed for monitor interface \n");
            return RETURN_ERR;
        }

        if ( wpa_ctrl_attach(g_wpa_monitor) != 0) {
            WIFI_LOG_INFO("wpa_ctrl_attach failed \n");
            return RETURN_ERR;
        }
        if (pthread_mutex_init(&wpa_sup_lock, NULL) != 0)
        {
            WIFI_LOG_INFO("mutex init failed\n");
            return RETURN_ERR;
        }
        /* Create thread to monitor events from wpa supplicant */
        pthread_attr_init(&thread_attr);
        pthread_attr_setstacksize(&thread_attr, 256*1024);
        
        ret = pthread_create(&monitor_thread, &thread_attr, monitor_thread_task, NULL);
        
        
        if (ret != 0) {        
            WIFI_LOG_INFO("Monitor thread creation failed \n");
            return RETURN_ERR;
        }
        // Start wpa_supplicant health monitor thread
        WIFI_LOG_INFO("Starting wpa_supplicant health monitor thread \n");
        ret = pthread_create(&wpa_health_mon_thread, NULL, monitor_wpa_health, NULL);
        if (ret != 0) {
            WIFI_LOG_INFO("WPA health monitor thread creation failed  \n");
            return RETURN_ERR;
        }
#ifdef WIFI_CLIENT_ROAMING
       // Initialize and set Roaming config params
       initialize_roaming_config();
#endif

       init_done=true;

       return RETURN_OK;
   }
  else {
    WIFI_LOG_WARN("wireless interface %s doesn't exist\n",
      g_ctx.conf.wlan_Interface);
    return RETURN_ERR;
  }
}

// Uninitializes wifi
INT wifi_uninit() {

    WIFI_LOG_INFO("Stopping monitor thread\n");

    WIFI_LOG_INFO("Disconnecting from the network\n");
    
    //check if "init_done" is not true (if previous init is not successful)
    //This helps to find if "wpa_health_mon_thread" created with a "pthread_create" during init or not.
    if(init_done == false) {
       WIFI_LOG_INFO("Previous wifi init is not successful\n");
       return RETURN_OK;
    }


    wpaCtrlSendCmd("DISCONNECT");
    wpaCtrlSendCmd("DISABLE_NETWORK 0");

    // adding a small sleep just to receive WPA_EVENT_DISCONNECTED
    // so that netsrvmgr can log a disconnected telemetry event
    wifi_usleep(1000000);

    if ((wpa_health_mon_thread) && ( pthread_cancel(wpa_health_mon_thread) == -1 )) {
        WIFI_LOG_ERROR( "[%s:%d] wpa health monitor thread cancel failed! \n",__FUNCTION__, __LINE__);
    }

    stop_monitor = true;
    pthread_join (wpa_health_mon_thread, NULL);
    pthread_join (monitor_thread, NULL);

    WIFI_LOG_INFO("Stopping wpa_supplicant service\n");
#ifndef RDKC
    system("systemctl stop wpa_supplicant");
#else
    system("/etc/init.d/wpa_supplicant.service stop");
#endif

    if (g_wpa_ctrl) {
      wpa_ctrl_close(g_wpa_ctrl);
      g_wpa_ctrl = NULL;
    }

    if (g_wpa_monitor) {
      wpa_ctrl_close(g_wpa_monitor);
      g_wpa_monitor = NULL;
    }

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
INT wifi_down()
{
  struct ifaddrs * addrs;
  WIFI_LOG_INFO("bringing down all wireless interfaces\n");

  if (getifaddrs(&addrs) == 0) {
    struct ifaddrs * itr;
    for (itr = addrs; itr; itr = itr->ifa_next) {
      if (itr->ifa_addr == NULL || itr->ifa_addr->sa_family != AF_PACKET)
        continue;
      if (wifi_interfaceIsWireless(itr->ifa_name)) {
        WIFI_LOG_INFO("bring down wireless interface %s", itr->ifa_name);
        wifi_interfaceSetEnabled(itr->ifa_name, false);
      }
    }
    freeifaddrs(addrs);
  }
  else {
    WIFI_LOG_WARN("error trying to disable wireless interfaces. getifaddrs failed. %d", errno);
  }

  return RETURN_OK;
}

#if 1
static void get_security_mode_and_encryption_type(const char* flags, char* auth, char* encrypt)
{
    const char* wpa2 = NULL;
    const char* wpa = NULL;
    const char* eap = NULL;
    const char* ccmp = NULL;
    const char* sae = NULL;
    const char* tkip = NULL;
    const char* wep = NULL;
    const char* none = NULL;
    
    wpa = strstr(flags, "WPA-");
    wpa2 = strstr(flags, "WPA2-");
    eap = strstr(flags, "EAP");
    ccmp = strstr(flags, "CCMP");
    sae = strstr(flags, "SAE");
    tkip = strstr(flags, "TKIP");
    wep = strstr(flags, "WEP");
    none = strstr(flags, "NONE");

    auth[0] = 0;
    encrypt[0] = 0;

    if(wpa)
        strcat(auth, "WPA-");
    if(wpa2)
        strcat(auth, "WPA2-");
    if(sae)
        strcat(auth, "WPA3-");
    if(eap)
        strcat(auth, "Enterprise-");
    if(wep)
        strcat(auth, "WEP-");
    if(none)
        strcat(auth, "None-");

    if(auth[0])
        auth[strlen(auth) - 1] = 0;
    else
    {
        WIFI_LOG_WARN("no auth flags recognized: %s\n", flags);
        return;
    }

    if(tkip)
        strcat(encrypt, "TKIP,");
    if(ccmp)
        strcat(encrypt, "AES,");

    if(encrypt[0])
        encrypt[strlen(encrypt) - 1] = 0;
    else if(wpa || wpa2)
        WIFI_LOG_WARN("no wpa encrypt flags recognized: %s\n", flags);
}
#else
static void get_security_mode_and_encryption_type(const char* wpa_supplicant_ap_flags, char* security_mode, char* encryption_type)
{
    int len = sizeof ( wifi_securityModes ) / sizeof ( wifi_securityModes[0] );
    for (int i = 0; i < len; i++)
    {
        if (NULL != strcasestr(wpa_supplicant_ap_flags, wifi_securityModes[i].apSecurityEncryptionString))
        {
            strcpy(security_mode, wifi_securityModes[i].modeString);
            strcpy(encryption_type, wifi_securityModes[i].encryptionString);
            return;
        }
    }
    WIFI_LOG_WARN("Unknown flag: %s\n", wpa_supplicant_ap_flags);
    security_mode[0] = '\0';
    encryption_type[0] = '\0';
}
#endif

static int is_zero_bssid(char* bssid) {
    if(bssid == NULL)
        return RETURN_ERR;
    else
        return strncmp(bssid,"00:00:00:00:00:00",17);
}

void wifi_getStats(INT radioIndex, wifi_sta_stats_t *stats)
{
    char *ptr     = NULL;
    char *saveptr = NULL;
    char *bssid, *ssid;
    int phyrate, noise, rssi,freq,avgRssi;
    int retStatus = -1;

    if(NULL == stats)
    {
        WIFI_LOG_ERROR("Input Stats is NULL \n");
        return;
    }

    bssid = NULL; ssid = NULL;

    /* Find the currently connected BSSID and run signal_poll command to get the stats */
    pthread_mutex_lock(&wpa_sup_lock);
    retStatus = wpaCtrlSendCmd("STATUS");
    if(retStatus == 0)
    {
        bssid = getValue(return_buf, "bssid");
        if (bssid == NULL)
        {
            WIFI_LOG_DEBUG("BSSID is NULL in Status output\n");
            goto exit;
        }
        else
            strcpy(stats->sta_BSSID, bssid);
        ptr = bssid + strlen(bssid) + 1;
        ssid = getValue(ptr, "ssid");
        if (ssid == NULL)
        {
            WIFI_LOG_DEBUG("SSID is NULL in Status output\n");
            goto exit;
        }
        printf_decode ((u8*)stats->sta_SSID, sizeof(stats->sta_SSID), ssid);


        if(wpaCtrlSendCmd("BSS current") == 0) {
            char* token = strtok_r(return_buf, "\n", &saveptr);
            while(token != NULL) {
                if(strncmp(token,"bssid=",6) == 0) {
                    // Check if we get proper BSSID from status no need to copy it
                    if(is_zero_bssid(stats->sta_BSSID) == RETURN_OK) {
                        sscanf(token,"bssid=%18s",stats->sta_BSSID);
                    }
                }
                // Get Security Mode from curent BSSID
                else if(strncmp(token,"flags=",6) == 0) {
                    char flags[64];
                    sscanf(token,"flags=%64s",flags);
                    get_security_mode_and_encryption_type(flags, stats->sta_SecMode, stats->sta_Encryption);
                    break;
                }
                token = strtok_r(NULL, "\n", &saveptr);
            }
        } else {
            WIFI_LOG_ERROR("Failed to get BSSID from BSS current\n");
        }

    } else {
        if (retStatus == -2)
            telemetry_event_d("WIFIV_WARN_hal_timeout", 1);
        WIFI_LOG_ERROR("wpaCtrlSendCmd(STATUS) failed - Ret = %d \n",retStatus);
        goto exit;
    }

    retStatus = wpaCtrlSendCmd("SIGNAL_POLL");
    if(retStatus == 0)
    {
        ptr = getValue(return_buf, "RSSI");

        if (ptr == NULL)
        {
            WIFI_LOG_ERROR("RSSI not in signal poll \n");
            goto exit;
        }
        else {
            rssi = atoi(ptr);
            stats->sta_RSSI = rssi;
        }
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "LINKSPEED");
        if (ptr == NULL)
        {
            WIFI_LOG_ERROR("LINKSPEED not in signal poll \n");
            goto exit;
        }
        else {
            phyrate = atoi(ptr);
            stats->sta_PhyRate = phyrate;
        }

        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "NOISE");
        if (ptr == NULL)
        {
            WIFI_LOG_ERROR("NOISE not in signal poll \n");
            goto exit;
        }
        else {
            noise = atoi(ptr);
            stats->sta_Noise = noise;
        }

        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "FREQUENCY");
        if(ptr == NULL)
        {
            WIFI_LOG_ERROR("FREQUENCY not in signal poll \n");
            goto exit;
        } else  {
            freq = atoi(ptr);
            WIFI_LOG_DEBUG("FREQUENCY=%d \t",freq);
            stats->sta_Frequency = freq;
            if((freq / 1000) == 2)
                strcpy(stats->sta_BAND,"2.4GHz");
            else if((freq / 1000) == 5)
                strcpy(stats->sta_BAND,"5GHz");
            else
                WIFI_LOG_ERROR("Unknown freq band.\n");
        }
        // Read Average RSSI
        ptr = ptr + strlen(ptr) + 1;
        ptr = getValue(ptr, "AVG_RSSI");
        if(ptr != NULL)
        {
            avgRssi = atoi(ptr);
            stats->sta_RSSI = avgRssi;
            WIFI_LOG_DEBUG("AVG_RSSI=%d \n",avgRssi);
        }
    }
    else
    {
        if (retStatus == -2)
            telemetry_event_d("WIFIV_ERR_hal_signalpolltimeout", 1);
        WIFI_LOG_ERROR("wpaCtrlSendCmd(SIGNAL_POLL) failed ret = %d\n",retStatus);
        goto exit;
    }
    char wifi_stats_buffer[128];
    snprintf(wifi_stats_buffer, sizeof(wifi_stats_buffer), "bssid=%s,ssid=%s,rssi=%d,phyrate=%d,noise=%d,Band=%s",
        stats->sta_BSSID, stats->sta_SSID, (int)stats->sta_RSSI, (int)stats->sta_PhyRate, (int)stats->sta_Noise, stats->sta_BAND);
    WIFI_LOG_INFO("%s\n", wifi_stats_buffer);
    telemetry_event_s("ap_info_split", wifi_stats_buffer);
exit:
    pthread_mutex_unlock(&wpa_sup_lock);
    return;
}

INT parse_scan_results(char *buf, size_t len)
{
    uint32_t count = 0;
    char tmp_str[100];
    char flags[256];
    char *delim_ptr, *ptr, *encrypt_ptr,*security_ptr;

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
    while (((delim_ptr=strchr(ptr, '\t')) != NULL) && (count < sizeof(ap_list)/sizeof(wifi_neighbor_ap_t))) {

        /* Parse bssid */
        memcpy(ap_list[count].ap_BSSID, ptr, (delim_ptr-ptr));
        ap_list[count].ap_BSSID[delim_ptr-ptr] = '\0';
/*        WIFI_LOG_INFO("bssid=%s \n",ap_list[count].ap_BSSID); */
     
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
/*        WIFI_LOG_INFO("freq=%s \n",ap_list[count].ap_OperatingFrequencyBand); */

        /* parse signal level */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(tmp_str, ptr, (delim_ptr-ptr));
        tmp_str[delim_ptr-ptr] = '\0';
        ap_list[count].ap_SignalStrength = atoi(tmp_str);
/*        WIFI_LOG_INFO("signal strength=%d \n",ap_list[count].ap_SignalStrength); */

        /* parse flags */
        ptr = delim_ptr + 1;
        delim_ptr=strchr(ptr, '\t');
        memcpy(flags, ptr, (delim_ptr-ptr));
        flags[delim_ptr-ptr] = '\0';
        memset(ap_list[count].ap_SecurityModeEnabled, 0, sizeof(ap_list[count].ap_SecurityModeEnabled));
        memset(ap_list[count].ap_EncryptionMode, 0, sizeof(ap_list[count].ap_EncryptionMode));
        encrypt_ptr=ap_list[count].ap_EncryptionMode;
        security_ptr=ap_list[count].ap_SecurityModeEnabled;
        get_security_mode_and_encryption_type(flags, security_ptr, encrypt_ptr);
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
        printf_decode ((u8*)ap_list[count].ap_SSID, 64, ptr);
        WIFI_LOG_INFO("decoded SSID=%s (encoded SSID=%s) BSSID=%s flags=%s SecuritymodeEnabled=%s EncryptionMode=%s\n",
                ap_list[count].ap_SSID, ptr, ap_list[count].ap_BSSID, flags, ap_list[count].ap_SecurityModeEnabled, ap_list[count].ap_EncryptionMode);
        // *delim_ptr='\n'; // put back the '\n' after printf_decode

        ptr = delim_ptr + 1;
        // increment ap_count only if bssid is filled properly
	// increment ap_count for non-empty SSIDs.
        if(ap_list[count].ap_BSSID[0] != '\0' && ap_list[count].ap_SSID[0] != '\0')
            count++;
    }

    return count;
}

INT wifi_getNeighboringWiFiDiagnosticResult(INT radioIndex, wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size) 
{
    size_t return_len=sizeof(return_buf)-1;
    int retry = 0;
    
    WIFI_LOG_INFO("Starting a single scan..\n");
    pthread_mutex_lock(&wpa_sup_lock);
    if (cur_scan_state == WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED) {
        WIFI_LOG_INFO("Scan is already in progress, Waiting for the scan results. \n");
    } else {
        WIFI_LOG_INFO("No in progress scanning, Starting a fresh scan.\n");
        bNoAutoScan=TRUE;
        wpaCtrlSendCmd("BSS_FLUSH 0");
        wpaCtrlSendCmd("SCAN");
        if (strstr(return_buf, "FAIL-BUSY") != NULL) {
            WIFI_LOG_ERROR("Scan command returned %s .. waiting \n", return_buf);            
            wpaCtrlSendCmd("BSS_FLUSH 0");
            wifi_usleep(1000000);
            wpaCtrlSendCmd("SCAN");
            if (strstr(return_buf, "FAIL-BUSY") != NULL) {
                WIFI_LOG_ERROR("Scan command returned %s FAILED \n", return_buf);
                goto exit_err;
            }
        }
        WIFI_LOG_INFO("Scan command returned %s \n", return_buf);
        cur_scan_state = WIFI_HAL_WPA_SUP_SCAN_STATE_STARTED;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    while ((cur_scan_state !=  WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) &&(retry++ < 1000)) {
      wifi_usleep(WPA_SUP_TIMEOUT);
    }
    pthread_mutex_lock(&wpa_sup_lock);    
    if (cur_scan_state != WIFI_HAL_WPA_SUP_SCAN_STATE_RESULTS_RECEIVED) { 
        WIFI_LOG_ERROR("Scan timed out retry times = %d \n",retry);
        //*output_array_size=0;
       // goto exit_err;
    } //else {
    WIFI_LOG_INFO("Trying to read Scan results \n"); // Lets read scan_results even if it is timed out FIX:- Xi-6 Scan timeout
    wpaCtrlSendCmd("SCAN_RESULTS");
    ap_count = parse_scan_results(return_buf, return_len);
    WIFI_LOG_INFO("Scan results contains %d BSSIDs. \n",ap_count);
    if (ap_count > 0) {
        int i;            
        *output_array_size = ap_count;
        *neighbor_ap_array = (wifi_neighbor_ap_t *)malloc(ap_count*sizeof(wifi_neighbor_ap_t));
            
        if(*neighbor_ap_array == NULL) {
            WIFI_LOG_INFO("Malloc Memory allocation failure\n");            
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
            WIFI_LOG_INFO("Setting scan Freq based on selected Band to - %s \n",freq_list_string);
            if(snprintf(cmd,BUF_SIZE,"SET freq_list %s",freq_list_string) < 0)
                return RETURN_ERR;
            pthread_mutex_lock(&wpa_sup_lock);
            wpaCtrlSendCmd(cmd);   //wpa_cli freq_list + bands returned from the above static function parsed results
            pthread_mutex_unlock(&wpa_sup_lock);
        }
        else
        {
            WIFI_LOG_INFO("Error in getting the Frequency list for specified Band, NOT SCANNING . \n");
            return RETURN_ERR;
        }
    }

    int timeout = 8;
    bssCount = get_wifi_self_steer_matching_bss_list(SSID,filtered_APList,timeout);  //setting time limit as 8 (to make scan complete)
    *output_array_size = bssCount;
    if(bssCount == 0)
    {
        WIFI_LOG_ERROR("No BSS found with given band and frequency \n");
        ret = RETURN_ERR;
    }
    else
    {
        WIFI_LOG_DEBUG("Found %d  BSS ids' for SSID %s \n",bssCount,SSID);
        *filtered_ap_array = (wifi_neighbor_ap_t *)malloc(bssCount*sizeof(wifi_neighbor_ap_t));
        if(*filtered_ap_array == NULL)
        {
            WIFI_LOG_INFO("Memory allocation failure\n");
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
        WIFI_LOG_ERROR("Error in getting supported bands.. Null string\n");
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
                WIFI_LOG_ERROR("Error in getting supported bands- Unable to get Freq Modes\n");
            }
        } else {
            WIFI_LOG_ERROR("Error in getting supported bands- Unable to Channel Capability\n");
        }
        pthread_mutex_unlock(&wpa_sup_lock);
    }
    WIFI_LOG_DEBUG("[%s:%d] SupportedFrequencyBands - %s\n",__FUNCTION__,__LINE__,output_string);
    return RETURN_OK;
}

INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) {

    int retStatus = RETURN_OK;
    CHAR frequency_string[8] = "";
    int frequency = 0;

    if(!output_string) {
        WIFI_LOG_ERROR("Error in getting supported bands.. Null string\n");
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
            WIFI_LOG_ERROR("[%s:%d] Failure in getting OperatingFrequencyBand \n",__FUNCTION__,__LINE__);
            retStatus = RETURN_ERR;
        }
    } else {
        WIFI_LOG_ERROR("[%s:%d] Failure in getting OperatingFrequencyBand - Failed to get Frequency\n",__FUNCTION__,__LINE__);
        retStatus = RETURN_ERR;
    }
    return retStatus;
}

INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) {

    FILE *fp = NULL;
    char cmd[BUFF_LEN_64];
    char result[BUFF_LEN_64];

    if (!output_string) {
        return RETURN_ERR;
    }

    snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"a,n,ac");
    memset(cmd,0,sizeof(cmd));
    memset(result,0,sizeof(result));

    // TODO: this isn't going to work with multiple wlan interfaces
    snprintf(cmd,sizeof(cmd),"iw phy | grep 'HE Iftypes'| tr '\n' ' '");
    fp = popen(cmd,"r");

    if (fp != NULL)
    {
      if (fgets(result, sizeof(result), fp)) {
        if (strstr(result,"HE Iftypes"))
          snprintf(output_string, 64, (radioIndex==0)?"b,g,n,ax":"a,n,ac,ax");
      }
      pclose(fp);
    }

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
            WIFI_LOG_ERROR("Invalid frequency band, Failure in getting Operating standard.\n");
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
    char *saveptr = NULL;

    pch = strtok_r(channelCap,"\n", &saveptr);
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
        pch = strtok_r (NULL, "\n", &saveptr);
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
       WIFI_LOG_ERROR("Error in getting channel capability.\n");
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
        WIFI_LOG_ERROR("Unable to get wireless interface name, Get bandwidth failed \n");
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
                WIFI_LOG_INFO("OperatingChannelBandwidth =  %s\n",output_string);
                ret = RETURN_OK;
            } else {
                WIFI_LOG_ERROR("Failure in getting bandwidth \n");
            }
        }
        else
        {
            WIFI_LOG_ERROR("Unable to read Channel width from iw \n");
            iw_info_failed=true;
        }
        pclose(fp);
    }
    else
    {
        WIFI_LOG_ERROR("popen() failed. failure in getting Channel Bandwidth\n");
        iw_info_failed=true;
    }

    if(true == iw_info_failed) //iw info fallback
    {
       WIFI_LOG_INFO("iw info command failed, fall back to iw link command\n");
       
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
                   bandwidth_token = strcasestr(bandwidth_string, "MHz");
                   if(NULL != bandwidth_token )
                   {   
                       strcpy(output_string,bandwidth_string); //copy bandwidth string to o/p string
                       bandwidth_found=true;
                       break;
                   }
               }
               if (true == bandwidth_found)
	       {
                   WIFI_LOG_INFO("OperatingChannelBandwidth =  %s\n",output_string);
                   ret = RETURN_OK;   
	       }
	       else
               {
                    WIFI_LOG_ERROR("MHz information missing in iw link o/p \n");
               }
           }
           else
           {
                WIFI_LOG_ERROR("Failure in getting bandwidth \n");
           }				
       }
       else
       {
          WIFI_LOG_ERROR("popen() failed. failure in getting Channel Bandwidth\n");
       }

    }
    return ret;
}

INT wifi_getSSIDName(INT apIndex, CHAR *output_string) {
    
    int ret = RETURN_ERR;
    if (output_string != NULL)
    {
        pthread_mutex_lock(&wpa_sup_lock);
        int retStatus = wpaCtrlSendCmd("STATUS");
        if (retStatus == -2)
            telemetry_event_d("WIFIV_WARN_hal_timeout", 1);
        char *ssid = getValue(return_buf, "\nssid"); // include '\n' to avoid a match with "bssid"
        if (ssid == NULL)
        {
            WIFI_LOG_ERROR( "%s: ssid not found in STATUS output\n", __FUNCTION__);
        }
        else
        {
            // TODO: assumes 'output_string' is at least MAX_SSID_LEN+1 big. wifi_getSSIDName needs 'max_len' 3rd arg to avoid assumption.
            printf_decode ((u8*)output_string, MAX_SSID_LEN+1, ssid);
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
    int retStatus = wpaCtrlSendCmd("STATUS");
    if (retStatus == -2)
        telemetry_event_d("WIFIV_WARN_hal_timeout", 1);
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
    
    char *bssid;
    
    pthread_mutex_lock(&wpa_sup_lock);
    int retStatus = wpaCtrlSendCmd("STATUS");
    if (retStatus == -2)
        telemetry_event_d("WIFIV_WARN_hal_timeout", 1);
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
    int retStatus = wpaCtrlSendCmd ("SIGNAL_POLL");
    if (retStatus == -2)
        telemetry_event_d("WIFIV_ERR_hal_signalpolltimeout", 1);
    if (NULL != (parameter_value = getValue(return_buf, parameter)))
    {
        strcpy (output_string, parameter_value);
        ret = RETURN_OK;
    }
    pthread_mutex_unlock (&wpa_sup_lock);

    WIFI_LOG_DEBUG( "[%s] return code = [%d], parameter = [%s], parameter_value = [%s]\n",
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
    if (retStatus == -3)
        telemetry_event_d("WIFIV_ERR_wpasupplicant_down", 1);
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
    g_wpa_ctrl = wpa_ctrl_open(g_ctx.ctrl_path);
    if(NULL != g_wpa_ctrl) {
        WIFI_LOG_INFO("wpa_supplicant control connection opened successfuly. \n");
    } else{
        WIFI_LOG_ERROR("Failure in opening wpa_supplicant control connection.\n");
        pthread_mutex_unlock(&wpa_sup_lock);
        return retStatus;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    
    // Open Monitor Connection
    pthread_mutex_lock(&wpa_sup_lock);
    wpa_ctrl_close(g_wpa_monitor);
    g_wpa_monitor = wpa_ctrl_open(g_ctx.ctrl_path);
    if(NULL != g_wpa_monitor) {
        WIFI_LOG_INFO("wpa_supplicant monitor connection opened successfuly. \n");
        if ( wpa_ctrl_attach(g_wpa_monitor) != 0) {
            WIFI_LOG_ERROR("wpa_ctrl_attach failed \n");
        } else {
            WIFI_LOG_INFO("Monitor connection Attached Successfully. \n");
            retStatus = 0;
        }
    } else{
        WIFI_LOG_ERROR("Failure in opening wpa_supplicant monitor connection.\n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return retStatus;
}
void* monitor_wpa_health(void* param)
{
    int retStatus = -1;
    int printInterval = 0;
    int pingCount = 0;
    int pingRecoveryCount = 0;
    (void)param;

    while(true)
    {
        retStatus = wifi_getWpaSupplicantStatus();
        if(retStatus == 0)
        {
            if(printInterval >= 4)
            {
                WIFI_LOG_INFO("wpa_supplicant heartbeat success. \n");
                printInterval = 0;
            }
            else
                printInterval++;
        }
        else
        { 
            WIFI_LOG_ERROR("wpa_supplicant heartbeat failed, Reason: %s \n",retStatus==-1?"No response.":"Command failure.");
            telemetry_event_d("WIFIV_ERR_HBFail", 1);
            pingCount = 0;
            WIFI_LOG_INFO("Trying for 5 continues pings...\n");
            while(pingCount < 5)
            {
                retStatus = wifi_getWpaSupplicantStatus();
                if(!retStatus) {
                    WIFI_LOG_INFO("wpa_supplicant heartbeat success. , Breaking Ping attempts\n");
                    // If the connection is alternatively failing for 3 times, Then it seems like an inconsistent connection, Lets reopen a new control connection. 
                    if(pingRecoveryCount >= 2) {
                        WIFI_LOG_INFO("wpa_supplicant heartbeat - inconsistent control connection: Reopen new one.\n");
                        wifi_openWpaSupConnection();
                        pingRecoveryCount = 0;
                    } else {
                        pingRecoveryCount++;
                    }
                    break; // Got one Success lets break
                }
                else
                {
                    WIFI_LOG_ERROR("wpa_supplicant heartbeat failed, Reason: %s, Attempt = %d\n",retStatus==-1?"No response.":"Command failure.",pingCount+1);
                    telemetry_event_d("WIFIV_ERR_HBFail", 1);
                }
                pingCount++;
                wifi_usleep(1000000 * 3);
            }
            if(pingCount >= 5) {
                 WIFI_LOG_INFO("Heartbeat failed for all attempts, Trying to reopen Connection.\n");
                 wifi_openWpaSupConnection();
            }
        }
        wifi_usleep(WPA_SUP_PING_INTERVAL * 1000000);
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

    WIFI_LOG_DEBUG( "[%s] return code = [%d], Channel Spec: %lu\n", __FUNCTION__, ret, *output_ulong);
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
    WIFI_LOG_INFO("SSID entries:1\n");
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
        WIFI_LOG_INFO("output struct is null");
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
                WIFI_LOG_ERROR("Error in parsing Radio Stats params \n");
            }
            output_struct->radio_PacketsSent = tx_packets;
            output_struct->radio_PacketsReceived = rx_packets;
            output_struct->radio_BytesSent = tx_bytes;
            output_struct->radio_BytesReceived = rx_bytes;
            output_struct->radio_ErrorsReceived = rx_err;
            output_struct->radio_ErrorsSent = tx_err;
            output_struct->radio_DiscardPacketsSent = tx_drop;
            output_struct->radio_DiscardPacketsReceived = rx_drop;
            WIFI_LOG_INFO("[tx_packets = %lld] [rx_packets =  %lld] [tx_bytes = %lld] [rx_bytes = %lld] [rx_err = %lld] [tx_err = %lld] [tx_drop = %lld] [rx_drop = %lld] \n",tx_packets,rx_packets,tx_bytes,rx_bytes,rx_err,tx_err,tx_drop,rx_drop);
        }
        else
        {
            WIFI_LOG_ERROR("Error in reading /proc/net/dev file \n");
        }
        pclose(fp);
    }
    else
    {
        WIFI_LOG_ERROR("Error in popen() : Opening /proc/net/dev failed \n");
    }
    pthread_mutex_lock(&wpa_sup_lock);
    int retStatus = wpaCtrlSendCmd("SIGNAL_POLL");
    if (retStatus == -2)
        telemetry_event_d("WIFIV_ERR_hal_signalpolltimeout", 1);
    ptr = getValue(return_buf, "NOISE");
    if(NULL != ptr)
    {
        noise = atoi(ptr);
        output_struct->radio_NoiseFloor = noise;
        WIFI_LOG_INFO("\n noise = %d ",noise);
    }
    else
    {
        WIFI_LOG_INFO("Noise is not available in siganl poll \n");
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return RETURN_OK;
}

INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool) {
    *output_bool = (g_wpa_monitor != NULL);
    WIFI_LOG_INFO("The radio is %s\n", g_wpa_monitor ? "enabled" : "not enabled");
    return RETURN_OK;
}

INT wifi_getRadioStatus(INT radioIndex, CHAR *output_string) {
    int ret = RETURN_ERR;
    char radio_status[20];
    char cli_buff[512];
    char *ptr = NULL;

    if(!output_string){
       WIFI_LOG_ERROR("Output_string is null\n");
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
            WIFI_LOG_INFO("\n WPA State : %s, Radio State :%s ",radio_status,output_string);
        }
        else
        {
            ret = RETURN_ERR;
            WIFI_LOG_INFO("Radio State is not available in wpa_cli STATUS \n");
        }
    }
    else
    {
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "/sys/class/net/%s/operstate", g_ctx.conf.wlan_Interface);

        char *operstate = wifi_readFile(path, true);
        if (operstate) {
            if (!strncasecmp(operstate, "up", 2)) {
                strcpy(output_string, "UP");
                ret = RETURN_OK;
            }
            else if (!strncasecmp(operstate, "down", 4)) {
                strcpy(output_string, "DOWN");
                ret = RETURN_OK;
            }
            else {
                WIFI_LOG_ERROR("failed to parse the operstate from %s. '%s'\n", 
		    path, operstate);
                ret = RETURN_ERR;
            }
            WIFI_LOG_INFO("The radio is %s (operstate=%s)\n", output_string, operstate);
            free(operstate);
      }
      else {
          ret = RETURN_ERR;
      }
    }
    return ret;
}

INT wifi_getRegulatoryDomain(INT radioIndex, CHAR* output_string){
    int ret = RETURN_ERR;
    if(!output_string){
       WIFI_LOG_INFO("Output_string is null\n");
       return ret;
    }
    pthread_mutex_lock(&wpa_sup_lock);
    int status = wpaCtrlSendCmd("GET COUNTRY");

    if(status == 0 && return_buf[0] != '\0'){
       if(snprintf(output_string, 4, "%s", return_buf) >= 0)
           ret = RETURN_OK;
    }
    else{
        ret = RETURN_ERR;
    }
    pthread_mutex_unlock(&wpa_sup_lock);
    return ret;
}

INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) {
    
    WIFI_LOG_INFO("MaxBitRate information will be implemented\n");
    return RETURN_ERR;
}

INT wifi_getRadioMCS(INT radioIndex, INT *output_INT){
    
    WIFI_LOG_INFO("MCS could not be determined\n");
    return RETURN_ERR;
}

INT wifi_getSSIDTrafficStats(INT ssidIndex, wifi_ssidTrafficStats_t *output_struct) {

    char filename[]="/tmp/wlparam.txt";
    char *bufPtr=NULL;
    char *saveptr = NULL;
    char *ptrToken;

    if(!output_struct) {
      WIFI_LOG_INFO("output struct is null");
      return 0;
    }
    system("wl counter > /tmp/wlparam.txt");
    bufPtr=wifi_readFile(filename, false);
    if(bufPtr)
    {
        ptrToken = strtok_r (bufPtr," \t\n", &saveptr);
        while (ptrToken != NULL)
        {
            if (strcmp(ptrToken, "txdatamcast") == 0)
            {
                ptrToken = strtok_r (NULL, " \t\n", &saveptr);
                output_struct->ssid_MulticastPacketsSent=strtoull(ptrToken, NULL, 10);
                WIFI_LOG_INFO("\n txdatamcast = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else if (strcmp(ptrToken, "txdatabcast") == 0)
            {
                ptrToken = strtok_r (NULL, " \t\n", &saveptr);
                output_struct->ssid_BroadcastPacketsSent=strtoull(ptrToken, NULL, 10);
                WIFI_LOG_INFO("\n txdatabcast = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else if (strcmp(ptrToken, "txnoack") == 0)
            {
                ptrToken = strtok_r (NULL, " \t\n", &saveptr);
                output_struct->ssid_ACKFailureCount=strtoull(ptrToken, NULL, 10);
                WIFI_LOG_INFO("\n txnoack  = %llu ",strtoull(ptrToken, NULL, 10));
            }
            else
            {
                ptrToken = strtok_r (NULL, " \t\n", &saveptr);
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

    WIFI_LOG_INFO("Extension channel is Auto\n");
    strcpy(output_string, "Auto");
    return RETURN_OK;
}

/***************Stubbed out functions**********************/
INT wifi_getRadioNumberOfEntries(ULONG *output) {
    WIFI_LOG_INFO("The radio number of entries is always 1\n");
    *output = 1;
    return RETURN_OK;
}

INT wifi_setRadioEnable(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) {
    strcpy(output_string, g_ctx.conf.wlan_Interface);
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

void wifi_initContext(wifi_context_t * ctx, wifi_halConfig_t *conf)
{
  memset(ctx, 0, sizeof(*ctx));
  if (!conf) {
    strcpy(ctx->conf.wlan_Interface, "wlan0");
  }
  else {
    strncpy(ctx->conf.wlan_Interface, conf->wlan_Interface, WLAN_IFNAMSIZ -1);
  }

  snprintf(ctx->ctrl_path, WLAN_PATHMAX, "/var/run/wpa_supplicant/%s", ctx->conf.wlan_Interface);
}

void wifi_interfaceSetEnabled(const char * ifname, bool enable)
{
  int ret;
  bool do_set;
  struct ifreq req;

  int soc = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (soc == -1) {
    WIFI_LOG_ERROR("error checking interface status, socket error. %s\n",
      strerror(errno));
    return;
  }

  do_set = false;
  memset(&req, 0, sizeof(req));
  strncpy(req.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);

  // read the current interface status.
  ret = ioctl(soc, SIOCGIFFLAGS, &req);
  if (ret == -1) {
    WIFI_LOG_ERROR("failed to get current state of interface %s. %s",
      ifname, strerror(errno));
    return;
  }

  if ((req.ifr_flags & IFF_UP) == IFF_UP) {
    if (!enable) {
      req.ifr_flags &= ~IFF_UP;
      do_set = true;
    }
  }
  else {
    if (enable) {
      req.ifr_flags |= IFF_UP;
      do_set = true;
    }
  }

  if (do_set) {
    ret = ioctl(soc, SIOCSIFFLAGS, &req);
    if (ret == -1) {
      WIFI_LOG_ERROR("failed to disable interface. %s\n", strerror(errno));
    }
  }
}

