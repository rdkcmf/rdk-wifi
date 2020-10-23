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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <wifi_common_hal.h>
#include "wifi_hal_priv.h"

static struct _wifi_sec_list
{
    wifiSecurityMode_t securityMode;
    const char         *modeString;
} wifi_securityModes[] =
{
    { WIFI_SECURITY_NONE,                 "No Security"                   },
    { WIFI_SECURITY_WEP_64,               "WEP (Open & Shared)"           },
    { WIFI_SECURITY_WEP_128,              "WEP (Open & Shared)"           },
    { WIFI_SECURITY_WPA_PSK_TKIP,         "WPA-Personal, TKIP encryp."    },
    { WIFI_SECURITY_WPA_PSK_AES,          "WPA-Personal, AES encryp."     },
    { WIFI_SECURITY_WPA2_PSK_TKIP,        "WPA2-Personal, TKIP encryp."   },
    { WIFI_SECURITY_WPA2_PSK_AES,         "WPA2-Personal, AES encryp."    },
    { WIFI_SECURITY_WPA_ENTERPRISE_TKIP,  "WPA-ENTERPRISE, TKIP"          },
    { WIFI_SECURITY_WPA_ENTERPRISE_AES,   "WPA-ENTERPRISE, AES"           },
    { WIFI_SECURITY_WPA2_ENTERPRISE_TKIP, "WPA2-ENTERPRISE, TKIP"         },
    { WIFI_SECURITY_WPA2_ENTERPRISE_AES,  "WPA2-ENTERPRISE, AES"          },
    { WIFI_SECURITY_NOT_SUPPORTED,        "Security format not supported" },
};

#ifdef WPA_SUPPLICANT
WIFI_HAL_GLOBAL g_wifi;

static int get_pid_from_file(char *pid_file, pid_t *pid_val)
{
    FILE *fp;
    char buf[BUF_SIZE];

    if( (fp=fopen(pid_file, "r")) == NULL)
        return RETURN_ERR;
    fscanf(fp, "%s", buf);
    fclose(fp);
    *pid_val=atoi(buf);
    if(*pid_val == 0)
        return RETURN_ERR;
    return RETURN_OK;
}
void wifi_hal_msg(const char *format, ...)
{
#ifndef DISABLE_WIFI_HAL_LOG
   char buf[4096];
   va_list argp;

   va_start(argp, format);
   vsnprintf(buf, sizeof(buf), format, argp);
   va_end(argp);
   fprintf(stderr, MODULE_NAME" # %s", buf);
#endif
   return;
}

int update_wpa_configuration(int factory_reset, int mem_only_psk, int update_config)
{
    /* Creating wpa_supplicant.conf if it does not already exist */
    if(access(WPA_SUPL_CONF, F_OK ) != -1 && !factory_reset)
        wifi_hal_msg("Configuration file present\n");
    else {
	system("mkdir -p /opt/wifi");
        FILE* fp;
        fp = fopen(WPA_SUPL_CONF, "w");
        if(fp == NULL){
            wifi_hal_msg("Error in opening configuration file\n");
            return RETURN_ERR;
        }
        fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
        if(mem_only_psk==ENABLE_MEM_PSK) /* Whether to enable storing PSK only in memory*/
            fprintf(fp, "mem_only_psk=1\n");
        if(update_config==ENABLE_CONFIG_UPDATE)
            fprintf(fp, "update_config=1\n");
        fclose(fp);
    }
    return RETURN_OK;
}

void wifi_hal_reset_data(void) {

    g_wifi.init_done=1;
    g_wifi.init_done=0;   /* Flag to check if WiFi init was already done or not */
    g_wifi.stop_monitor=0;  /* Flag to stop the monitor thread */
    g_wifi.kill_wpa_supplicant=0; /* Flag to kill wpa_supplicant */

    g_wifi.sup_pid=0;
    g_wifi.ctrl_handle = NULL;
    g_wifi.monitor_handle = NULL; 
    g_wifi.cur_scan_state = WIFI_HAL_SCAN_STATE_IDLE;

    g_wifi.update_ssid_info=1;
    g_wifi.persist_ssid_enabled=0;      /* Whether to save to a conf file - Default value is 1 (Will save) */ 
}

// Initializes the wifi subsystem (all radios)
INT wifi_init() {
#define MAX_RETRY 10
    int retry = 0;
    pid_t pid;
    g_wifi.stop_monitor=0;
    g_wifi.kill_wpa_supplicant=0;
    pthread_attr_t thread_attr;
    pthread_t monitor_thread;
    int ret;

    wifi_hal_msg("wifi_init() entered \n");
    if(g_wifi.init_done == 1) {
       wifi_hal_msg("Wifi init has already been done\n");
       return RETURN_OK;
    }
    if (g_wifi.sup_pid != 0)	{
        wifi_hal_msg("wifi_init called again \n");
        wifi_hal_msg("%s(): wpa_supplicant already started", __FUNCTION__);		
    }

    wifi_hal_reset_data(); /*reset counters and states*/
    update_wpa_configuration(0, DISABLE_MEM_PSK, ENABLE_CONFIG_UPDATE);
    /* Kill the existing wpa_supplicant process */
    if(get_pid_from_file(WPA_SUPL_PIDFILE, &pid) == 0)
        kill(pid, SIGKILL);   
    system("rm -f /var/run/wpa_supplicant/wlan0");
 
    wifi_hal_msg("Starting wpa_supplicant \n");
    system("wpa_supplicant -B -Dnl80211 -c/opt/wifi/wpa_supplicant.conf -iwlan0 -P/var/run/wpa_supplicant/wlan0.pid");
    
    while (g_wifi.ctrl_handle==NULL) {
        g_wifi.ctrl_handle = wpa_ctrl_open(WPA_SUPL_CTRL);
        if (retry++ > MAX_RETRY) break;
        sleep(1);
    }

    if (g_wifi.ctrl_handle == NULL) {
        wifi_hal_msg("wpa_ctrl_open failed for control interface \n");
        return RETURN_ERR;
    }
    g_wifi.monitor_handle = wpa_ctrl_open(WPA_SUPL_CTRL);
    if ( g_wifi.monitor_handle == NULL ) {
        wifi_hal_msg("wpa_ctrl_open failed for monitor interface \n");
        return RETURN_ERR;
    }

    if ( wpa_ctrl_attach(g_wifi.monitor_handle) != 0) {
        wifi_hal_msg("wpa_ctrl_attach failed \n");
        return RETURN_ERR;
    }
    if (pthread_mutex_init(&g_wifi.sup_lock, NULL) != 0) {
        wifi_hal_msg("mutex init failed\n");
        return RETURN_ERR;
    }

    /* Create thread to monitor events from wpa supplicant */
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, 256*1024);
    
    if(pthread_create(&monitor_thread, &thread_attr, wifi_event_monitor_thread, NULL) != 0) {
        wifi_hal_msg("Thread creation failed for wifi_event_monitor_thread() \n");
        return RETURN_ERR;
    }
    g_wifi.init_done=1;

    return RETURN_OK;
}

/* Un-initialize Wifi : disable networks and stop daemons */
INT wifi_uninit() {
    char result[64];
    wifi_hal_msg("Stopping monitor thread\n");
    pid_t pid; 
    g_wifi.stop_monitor=1;

    wifi_hal_msg("Disconnecting from the network\n");

    send_wpa_cli_command(result, sizeof(result)-1, "DISCONNECT");
    send_wpa_cli_command(result, sizeof(result)-1, "DISABLE_NETWORK 0");
    
    while(g_wifi.kill_wpa_supplicant != 1)
         sleep(1);    

    wifi_hal_msg("Killing wpa_supplicant process\n");
    /* Kill the existing wpa_supplicant process */
    if(get_pid_from_file(WPA_SUPL_PIDFILE, &pid) == 0)
       kill(pid, SIGKILL);
    
    g_wifi.init_done=0;
    return RETURN_OK;
}

//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string)
{
    snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);
    return RETURN_OK;
}

//clears internal variables to implement a factory reset of the Wi-Fi subsystem
INT wifi_factoryReset() {
    wifi_uninit();
    wifi_hal_msg("Resetting the configuration file, this will wipe saved SSIDs\n");
    update_wpa_configuration(1, DISABLE_MEM_PSK, ENABLE_CONFIG_UPDATE);
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

    wifi_hal_msg("Bring the wlan interface down, default interface :wlan0\n");
    system("ifdown wlan0");
    return RETURN_OK;
}

/* wpa_cli output:
  > bssid 		/ frequency / signal level / flags 	/		ssid
    84:d4:7e:bf:d0:c0  2437	      -53	     [WPA2-EAP-CCMP][ESS]	wirelesstata@telxsi.com
*/
INT parse_scan_results(char *res_buf)
{
    uint32_t count = 0, token, enc_mode_found=0;
    wifi_neighbor_ap_t *cur_ap;
    char signal_str[64];
    char flags[256];
    char *start_ptr, *end_ptr, *encrypt_ptr;
    
    if(!res_buf) return -1;
  
#define SCAN_HEADER "bssid / frequency / signal level / flags / ssid"
    if(strncmp(res_buf, SCAN_HEADER, sizeof(SCAN_HEADER)-1)!=0) {
        wifi_hal_msg("Scan result header mismatch, result format might have changed, [%s]\n",res_buf);
        return -1;
    }
    /*Skip first line (Header)*/
    if( (start_ptr=strchr(res_buf,'\n')) == NULL) return -1;
    start_ptr++;

/*get next token separated by delimeter, copy a string from current positon upto position of 'end'*/
#define COPY_NEXT_TOKEN(output, start, end, delim) { \
    if(token>0) { end=strchr(start, delim);}         \
    memcpy(output, start, (end-start));              \
    output[end-start] = '\0';                        \
    start=end+1;                                     \
    wifi_hal_dbg(#output"=%s\n",output);             \
    token++;                                         \
}
/*Append encryption mode string to supplied input if matched*/
#define APPEND_SEC_MODE_IF_MATCH(flag, sec, type) {                     \
    if (strstr(flag, sec)) {                                            \
        strcpy(encrypt_ptr, wifi_securityModes[type].modeString);       \
        encrypt_ptr[strlen(wifi_securityModes[type].modeString)] = ','; \
        encrypt_ptr += strlen(wifi_securityModes[type].modeString) + 1; \
        enc_mode_found++;                                               \
    }                                                                   \
}
    /* Parse scan results */
    while ((end_ptr=strchr(start_ptr, '\t')) != NULL) {
        token=0;
        cur_ap=&g_wifi.ap_list[count]; 

        /*BSSID*/
        COPY_NEXT_TOKEN(cur_ap->ap_BSSID, start_ptr, end_ptr, '\t');

        /*Frequency*/
        COPY_NEXT_TOKEN(cur_ap->ap_OperatingFrequencyBand, start_ptr, end_ptr, '\t');

        /*Signal Strength*/
        COPY_NEXT_TOKEN(signal_str, start_ptr, end_ptr, '\t');
        cur_ap->ap_SignalStrength = atoi(signal_str);

        /*flags (Encryption Mode)*/ 
        COPY_NEXT_TOKEN(flags, start_ptr, end_ptr, '\t');
        memset(cur_ap->ap_EncryptionMode, 0, sizeof(cur_ap->ap_EncryptionMode));
        encrypt_ptr = cur_ap->ap_EncryptionMode;

	APPEND_SEC_MODE_IF_MATCH(flags, "WEP",                  WIFI_SECURITY_WEP_64);
	APPEND_SEC_MODE_IF_MATCH(flags, "[WPA-PSK-CCMP]",       WIFI_SECURITY_WPA_PSK_AES);
	APPEND_SEC_MODE_IF_MATCH(flags, "[WPA-PSK-TKIP]",       WIFI_SECURITY_WPA_PSK_TKIP);
	APPEND_SEC_MODE_IF_MATCH(flags, "[WPA-PSK-CCMP+TKIP]",  WIFI_SECURITY_WPA_PSK_AES);
	APPEND_SEC_MODE_IF_MATCH(flags, "[WPA2-PSK-CCMP]",      WIFI_SECURITY_WPA2_PSK_AES);
	APPEND_SEC_MODE_IF_MATCH(flags, "[WPA2-PSK-TKIP]",      WIFI_SECURITY_WPA2_PSK_TKIP);
	APPEND_SEC_MODE_IF_MATCH(flags, "[WPA2-PSK-CCMP+TKIP]", WIFI_SECURITY_WPA2_PSK_TKIP);
        if(enc_mode_found>0) *(encrypt_ptr-1)='\0';
        wifi_hal_dbg("EncryptionMode=%s\n", cur_ap->ap_EncryptionMode);
        enc_mode_found=0;
        /*SSID*/ 
        COPY_NEXT_TOKEN(cur_ap->ap_SSID, start_ptr, end_ptr, '\n');

        if(count>=MAX_AP_SUPPORTED-1) {
            wifi_hal_dbg("!!! WARNING - Scan reached Maximum supported AP (%d), stopping...\n", MAX_AP_SUPPORTED);
            break;
        }
        count++;
    }
    printf("Total AP Count=%d\n",count);
    return count;
}

INT wifi_getNeighboringWiFiDiagnosticResult(INT radioIndex, wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size) 
{
    int retry = 0;
    uint32_t ap_found=0;
    char long_result_str[4096];
    size_t result_len=sizeof(long_result_str)-1;
 
    wifi_hal_msg("Starting a single scan..\n");

    int ret=0;
    G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
    if(ret==-EBUSY) return -1;

    if (g_wifi.cur_scan_state != WIFI_HAL_SCAN_STATE_IDLE) {
        wifi_hal_msg("Scan is in progress \n");
        goto exit_err;
    }
    
    if(send_wpa_cli_command(long_result_str, result_len, "SCAN")==WPA_SUP_CMD_INIT_ERR) {
        goto exit_err;
    }
 
    while (strstr(long_result_str, "FAIL-BUSY") != NULL) {
        wifi_hal_msg("Scan command returned %s .. waiting \n", long_result_str);            
        G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
        sleep(1); 
        G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
        send_wpa_cli_command(long_result_str, result_len, "SCAN");
    }
    wifi_hal_msg("Scan command returned %s\n", long_result_str);

    g_wifi.cur_scan_state = WIFI_HAL_SCAN_STATE_CMD_SENT;
    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    while ((g_wifi.cur_scan_state !=  WIFI_HAL_SCAN_STATE_RESULTS_RECEIVED) &&(retry++ < 100)) {       
        usleep(WPA_SUP_TIMEOUT);
    }
    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);    
    if (g_wifi.cur_scan_state != WIFI_HAL_SCAN_STATE_RESULTS_RECEIVED) { 
        wifi_hal_msg("Scan timed out\n");
        *output_array_size=0;
        goto exit_err;
    } else {
        wifi_hal_msg("Scan results received \n");
        send_wpa_cli_command(long_result_str, result_len, "SCAN_RESULTS");
        ap_found = parse_scan_results(long_result_str);
        if (ap_found > 0) {
            int i;            
            *output_array_size = ap_found;
            if( (*neighbor_ap_array = (wifi_neighbor_ap_t *)malloc(ap_found*sizeof(wifi_neighbor_ap_t))) == NULL ) {
                wifi_hal_msg("Memory allocation failure\n");            
                goto exit_err;
            }
            for (i=0; i<*output_array_size; i++)
                (*neighbor_ap_array)[i] = g_wifi.ap_list[i];
        }        
    }
   g_wifi.cur_scan_state = WIFI_HAL_SCAN_STATE_IDLE;
   G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
   return RETURN_OK;

 exit_err:   
   g_wifi.cur_scan_state = WIFI_HAL_SCAN_STATE_IDLE;
   G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
   return RETURN_ERR; 
}

INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string) {
    UNUSED_VAR(radioIndex);
    if(!output_string) {
        wifi_hal_msg("Error in getting supported bands.. Null string\n");
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "5GHz");
    return RETURN_OK;
}

INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) {
    UNUSED_VAR(radioIndex);
    if(!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "5GHz");
    return RETURN_OK;
}

INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) {
    UNUSED_VAR(radioIndex);
    if (!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"n,ac");
    return RETURN_OK;
}

INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly) {
    UNUSED_VAR(radioIndex);
    if(!output_string) {
        return RETURN_ERR;
    }
    wifi_hal_msg("Test mode\n");
    return RETURN_OK;
}

INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string) {
    UNUSED_VAR(radioIndex);
    if(!output_string) {
        return RETURN_ERR;
    }
    snprintf(output_string, 64, "%s", (radioIndex==0)?"1-11":"36,40");
    return RETURN_OK;
}

INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) {
   API_NOT_IMPLEMENTED; 
}

INT wifi_getSSIDName(INT apIndex, CHAR *output_string) {
    
    char *ptr, *bssid, *ssid;
    char result[512];

    int ret=0;
    G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
    if(ret==-EBUSY) return -1;

    send_wpa_cli_command(result, sizeof(result)-1, "STATUS");
    bssid = parse_token(result, "bssid", "=");
    if (bssid == NULL) 
        goto exit_err;
    ptr = bssid + strlen(bssid) + 1;
    ssid = parse_token(ptr, "ssid", "=");
    wifi_hal_dbg("ssid=%s \n", ssid);
    if (ssid == NULL) 
        goto exit_err;
    else
        if (output_string != NULL) strcpy(output_string, ssid);

    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    return RETURN_OK;

exit_err:
    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    return RETURN_ERR;
}

INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string) {

    return RETURN_OK;
}

INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string) {
    
    return RETURN_OK;
}

INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) {
    
    char *ptr, *bssid;
    char result[64];
    
    int ret;
    G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
    if(ret==-EBUSY) return -1;

    send_wpa_cli_command(result, sizeof(result)-1, "STATUS");
    bssid = parse_token(result, "bssid", "=");
    if (bssid == NULL) 
        goto exit_err;
    else
        if (output_string != NULL) strcpy(output_string, bssid);
            
    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    return RETURN_OK;

exit_err:
    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    return RETURN_ERR;
}

INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong) {

    if(!output_ulong) {
        return RETURN_ERR;
    }

    return RETURN_ERR;
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
    wifi_hal_msg("SSID entries:1\n");
    return RETURN_OK;

}

INT wifi_getRadioTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct) {

   if(!output_struct) {
       return -1;
   }
   FILE *proc_f;
   char cmd[96];
   char result[256];

   sprintf(cmd, "cat /proc/net/dev|grep wlan0|tr -s ' '|cut -f 3-6,11-14 -d ' '");
   if( (proc_f = popen(cmd, "r"))== NULL) {
       wifi_hal_msg("Unable to open /proc/net/dev\n");
       return -1;
   }

   ULONG tx_bytes=0,tx_pkts=0, tx_errs=0, tx_drop=0;
   ULONG rx_bytes=0,rx_pkts=0, rx_errs=0, rx_drop=0;
   if (fgets(result, sizeof(result)-1, proc_f) == NULL) {
       wifi_hal_msg("Unable to read from command result\n");
       return -1;
   }
   sscanf(result, "%u %u %u %u %u %u %u %u",&tx_bytes, &tx_pkts, &tx_errs, &tx_drop, &rx_bytes, &rx_pkts, &rx_errs, &rx_drop);
   
   output_struct->radio_BytesReceived = rx_bytes;
   output_struct->radio_PacketsReceived = rx_pkts;
   output_struct->radio_ErrorsReceived = rx_errs;
   output_struct->radio_DiscardPacketsReceived = rx_drop;
   output_struct->radio_BytesSent = tx_bytes;
   output_struct->radio_PacketsSent = tx_pkts;
   output_struct->radio_ErrorsSent = tx_errs;
   output_struct->radio_DiscardPacketsSent = tx_drop;
   wifi_hal_dbg("Traffic Statistics:\n\t TX [Bytes:%u, PKT:%u, Err:%u, Discard:%u]\n\t RX [Bytes:%u, PKT:%u, Err:%u, Discard:%u]\n",\
 output_struct->radio_BytesSent, output_struct->radio_PacketsSent, output_struct->radio_ErrorsSent, output_struct->radio_DiscardPacketsSent,\
output_struct->radio_BytesReceived, output_struct->radio_PacketsReceived, output_struct->radio_ErrorsReceived, output_struct->radio_DiscardPacketsReceived);
    return RETURN_OK;
}

INT wifi_getRadioStatus(INT radioIndex, CHAR *output_string) {
    if ( g_wifi.monitor_handle != NULL ){
        strcpy(output_string, "UP");
        wifi_hal_msg("The radio is enabled\n");
        return RETURN_OK;
    }
    
    strcpy(output_string, "DOWN");
    return RETURN_ERR;
}

INT wifi_getRegulatoryDomain(INT radioIndex, CHAR* output_string){
     
    if(!output_string){
       wifi_hal_msg("Output_string is null\n");
       return RETURN_ERR;
    }
    strcpy(output_string, "US");
    wifi_hal_msg("Regulatory domain:US\n");
    return RETURN_OK; 
}

INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) {
    UNUSED_VAR(radioIndex);
    char *link_speed;
    char result[128];

    if(!output_string) {
        return RETURN_ERR;
    }

    int ret=0;
    G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
    if(ret==-EBUSY) return -1;

    send_wpa_cli_command(result, sizeof(result)-1, "SIGNAL_POLL");
    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    if( (link_speed = parse_token(result, "LINKSPEED", "=")) == NULL)
        return RETURN_ERR;

    sprintf(output_string, "%s Mb/s",link_speed);
    return RETURN_OK;
}

INT wifi_getRadioMCS(INT radioIndex, INT *output_INT){
   API_NOT_IMPLEMENTED; 
}

INT wifi_getSSIDTrafficStats(INT ssidIndex, wifi_ssidTrafficStats_t *output_struct) {
   API_NOT_IMPLEMENTED; 
}

INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) {

    wifi_hal_msg("Extension channel is Auto\n");
    strcpy(output_string, "Auto");
    return RETURN_OK;
}
#endif /*WPA_SUPPLICANT*/

/***************Stubbed out functions**********************/
INT wifi_getRadioNumberOfEntries(ULONG *output) {
    wifi_hal_msg("Currently a single Radio is supported\n");
    *output = 1;
    return RETURN_OK;
}

INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool) {
    if (output_bool) {
        *output_bool = TRUE;
    }
    return RETURN_OK;
}

INT wifi_setRadioEnable(INT radioIndex, BOOL enable) {
    return RETURN_OK;
}

INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) {
    if(output_string) strcpy(output_string, "wlan0");
    return RETURN_OK;
}

INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioChannel(INT radioIndex, ULONG channel) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioMCS(INT radioIndex, INT MCS) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioTransmitPower(INT radioIndex, INT *output_INT) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioChannelSwitchingCount(INT radioIndex, INT *output) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) {
    API_NOT_IMPLEMENTED;
}

INT wifi_applyRadioSettings(INT radioIndex) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) {
    API_NOT_IMPLEMENTED;
}

INT wifi_applySSIDSettings(INT ssidIndex) {
    API_NOT_IMPLEMENTED;
}

INT wifi_getSpecificSSIDInfo(const char* SSID, WIFI_HAL_FREQ_BAND band, wifi_neighbor_ap_t **filtered_ap_array, UINT *output_array_size) {
    API_NOT_IMPLEMENTED;
}

INT wifi_setRadioScanningFreqList(INT radioIndex, const CHAR *freqList) {
    API_NOT_IMPLEMENTED;
}

