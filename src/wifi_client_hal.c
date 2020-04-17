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

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>

#include <wifi_client_hal.h>
#include "wifi_hal_priv.h"

/*Call backs which will be invoked when client automatically connect/disconnect with AP. */
wifi_connectEndpoint_callback callback_connect;
wifi_disconnectEndpoint_callback callback_disconnect;

#ifdef WPA_SUPPLICANT
extern WIFI_HAL_GLOBAL g_wifi;

char* parse_token(char *input, char *keyword, const char *delim) {
    char *ptr;
 
    if((ptr = strstr(input, keyword)) == NULL) return NULL;
    strtok(ptr, delim);
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

int send_wpa_cli_command(char *reply, size_t reply_len, char *cmd, ...) {
    char cmd_buf[WPA_SUP_CMD_MAX];
    int ret;
   
    va_list argp;
    va_start(argp, cmd);
    vsnprintf(cmd_buf, sizeof(cmd_buf), cmd, argp);
    va_end(argp);
 
   /* clear previous result string. */
    memset(reply, 0, reply_len);

    if(!g_wifi.ctrl_handle) {
        wifi_hal_msg("%s: cmd=%s, error=init_err\n",__func__,cmd_buf);
        return WPA_SUP_CMD_INIT_ERR;
    }

    ret = wpa_ctrl_request(g_wifi.ctrl_handle, cmd_buf, strlen(cmd_buf), reply, &reply_len, NULL);
 
    if (ret == WPA_SUP_CMD_TIMEOUT) {
        wifi_hal_msg("%s : cmd=%s, error=timeout \n", __func__, cmd_buf);
        return WPA_SUP_CMD_TIMEOUT;
    } else if (ret < 0) {
        wifi_hal_msg("%s: cmd=%s, error=failed \n", __func__, cmd_buf);
        return WPA_SUP_CMD_FAILED;
    }
    return 0;        
}


/* Monitoring thread, sends state messages to wifi service manager */
void* wifi_event_monitor_thread(void *param)
{
    wifi_hal_msg("Inside %s\n", __func__);
    size_t event_buf_len;
    char *start;
    char *ptr;
    char *curr_ssid;                       /* Store the name of the SSID here to send back to Network Service Manager */
    char *curr_bssid;                      /* Store the name of the BSSID here to send back to Network Service Manager */
    char ssid[64];
    char event_buf[512];                  /* Buffer to store the event results */
    char result_buf[4096];
    
    wifiStatusCode_t connStatus;

    while ((g_wifi.stop_monitor != 1) && (g_wifi.monitor_handle != NULL)) {
        if (wpa_ctrl_pending(g_wifi.monitor_handle) > 0) {            
            
            memset(event_buf, 0, sizeof(event_buf));
            event_buf_len = sizeof(event_buf) - 1;
            
            if (0 == wpa_ctrl_recv(g_wifi.monitor_handle, event_buf, &event_buf_len)) {
                start = strchr(event_buf, '>');
                if (start == NULL) continue;
                if (strstr(start, WPA_EVENT_SCAN_STARTED) != NULL) {
                    wifi_hal_msg("Scanning started \n");
                    
                    /* Flush the BSS everytime so that there is no stale information */
                    wifi_hal_msg("Flushing the BSS now\n");
                    send_wpa_cli_command(result_buf, sizeof(result_buf)-1, "BSS_FLUSH 0");
                    
                    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                    if (g_wifi.cur_scan_state == WIFI_HAL_SCAN_STATE_CMD_SENT)
                        g_wifi.cur_scan_state = WIFI_HAL_SCAN_STATE_STARTED;
                    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                } 
                
                else if (strstr(start, WPA_EVENT_SCAN_RESULTS) != NULL) {
                    wifi_hal_msg("Scanning results received \n");
                    if (g_wifi.cur_scan_state == WIFI_HAL_SCAN_STATE_STARTED) {
                        G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                        g_wifi.cur_scan_state = WIFI_HAL_SCAN_STATE_RESULTS_RECEIVED;
                        G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                    }
                }
                else if((strstr(start, WPS_EVENT_AP_AVAILABLE_PBC) != NULL)){
                    wifi_hal_msg("WPS Connection in progress\n");
                    connStatus = WIFI_HAL_CONNECTING;
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, ssid, &connStatus);
                } 
 
                else if(strstr(start, WPS_EVENT_TIMEOUT) != NULL) {
                    wifi_hal_msg("WPS Connection timeout\n");
                    connStatus = WIFI_HAL_ERROR_NOT_FOUND;
                    if (callback_disconnect) (*callback_disconnect)(1, "", &connStatus);
                }

                else if(strstr(start, WPS_EVENT_SUCCESS) != NULL) {
                    wifi_hal_msg("WPS is successful...Associating now\n");
                }
                
                else if(strstr(start, WPA_EVENT_CONNECTED) != NULL) {
                    wifi_hal_msg("Authentication completed successfully and data connection enabled\n");
                    
                    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                    send_wpa_cli_command(result_buf, sizeof(result_buf)-1,"STATUS");
                    
                    /* Returning the BSSID that the client is connected to */
                    curr_bssid = parse_token(result_buf, "bssid", "=");
                    wifi_hal_msg("bssid=%s \n", curr_bssid);
                    
                    ptr = curr_bssid + strlen(curr_bssid) + 1;
                    /* Returning the SSID that the client is connected to */
                    curr_ssid = parse_token(ptr, "ssid", "=");
                    wifi_hal_msg("ssid=%s \n", curr_ssid);
                    
                    wifi_hal_msg("Successfully connected to AP:%s\n", curr_ssid);
                    strcpy(ssid, curr_ssid);
                    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                    
                    connStatus = WIFI_HAL_SUCCESS;
                    
                    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                    /* Save the BSSID in the configuration file */
                    send_wpa_cli_command(result_buf, sizeof(result_buf)-1, "SET_NETWORK 0 bssid %s",curr_bssid);
                    
                    /* Save the configuration */
                    if(g_wifi.persist_ssid_enabled){
                        send_wpa_cli_command(result_buf, sizeof(result_buf)-1,"SAVE_CONFIG");
			g_wifi.update_ssid_info=1;
                    }
                    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                    wifi_hal_msg("The SSID is:%s\n", ssid);
                    /* Trigger callback to Network Service Manager */
                    if (callback_connect) (*callback_connect)(1, ssid, &connStatus);
                }
                
                else if(strstr(start, WPA_EVENT_DISCONNECTED) != NULL) {
                    
                    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                    send_wpa_cli_command(result_buf, sizeof(result_buf)-1,"GET_NETWORK 0 ssid");
                    wifi_hal_msg("Disconnected from the network:%s\n", result_buf);
                    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                    connStatus = WIFI_HAL_SUCCESS;
                    if (callback_disconnect) (*callback_disconnect)(1, result_buf, &connStatus);
                }
                
                else if(strstr(start, WPA_EVENT_TEMP_DISABLED) != NULL){
                    wifi_hal_msg("Network authentication failure (Incorrect password)\n");
                    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                    /* Get the SSID that is currently in the conf file */
                    send_wpa_cli_command(result_buf, sizeof(result_buf)-1,"GET_NETWORK 0 ssid");
                    
                    wifi_hal_msg("Disconnected from the network:%s\n", result_buf);
                    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                    connStatus = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
                    (*callback_connect)(1, result_buf, &connStatus);
                }
                
                else if(strstr(start, WPA_EVENT_NETWORK_NOT_FOUND) != NULL) {
                    wifi_hal_msg("Received a network not found event\n");
                    connStatus = WIFI_HAL_ERROR_NOT_FOUND;
                    
                    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
                    /* Get the BSSID of the last connected network */
                    send_wpa_cli_command(result_buf, sizeof(result_buf)-1, "GET_NETWORK 0 bssid");
                    
                    if(strstr(result_buf,"FAIL") != NULL){
                        wifi_hal_msg("Not Connected to any SSID previously or previous info has been cleared\n");
                        connStatus = WIFI_HAL_ERROR_NOT_FOUND;
                        G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                    }
                    else{
                        char prev_result[64];
                        strncpy(prev_result, result_buf, sizeof(prev_result)-1); prev_result[64]='\0';
                        /* Pass in the BSSID to the supplicant and check if the AP exists */
                        send_wpa_cli_command(result_buf, sizeof(result_buf)-1, "BSS %s", prev_result);
                        
                        /* Check whether AP is in range or not */
                        if(strcmp(result_buf,"") == 0) {
                            wifi_hal_msg("The AP is down or not within range\n");
                            send_wpa_cli_command(result_buf, sizeof(result_buf)-1, "GET_NETWORK 0 ssid");
                            G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                            if (callback_disconnect) (*callback_disconnect)(1, result_buf, &connStatus);
                        }
                        else{ /* Check whether the SSID has changed */
                            
                            wifi_hal_msg("The SSID of the AP has changed\n");
                            connStatus = WIFI_HAL_ERROR_SSID_CHANGED;
                            /* Get the ssid info from the config file */
                            send_wpa_cli_command(result_buf, sizeof(result_buf)-1, "GET_NETWORK 0 ssid");
                            G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
                            if (callback_disconnect) (*callback_disconnect)(1, result_buf, &connStatus);
                        }
                    } /* else part for checking if BSS has bssid */ 
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
    g_wifi.kill_wpa_supplicant=1;        
    return NULL;
} /* End monitor_thread function */


void wifi_getStats(INT radioIndex, wifi_sta_stats_t *stats)
{
    char *ptr;
    char *bssid, *ssid;
    char result[512];
    int phyrate, noise, rssi;
    int ret=0;
 
    /* Find the currently connected BSSID and run bss command to get the stats */
    G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
    if(ret==-EBUSY) return;

    send_wpa_cli_command(result, sizeof(result)-1, "STATUS");
    bssid = parse_token(result, "bssid", "=");
    if (bssid == NULL) 
        goto exit;
    else
        if (stats != NULL) strcpy(stats->sta_BSSID, bssid);
    ptr = bssid + strlen(bssid) + 1;
    ssid = parse_token(ptr, "ssid", "=");
    if (ssid == NULL) 
        goto exit;
    else
        if (stats != NULL) strcpy(stats->sta_SSID, ssid);

    send_wpa_cli_command(result, sizeof(result)-1, "BSS %s", bssid);    
    ptr = parse_token(result, "noise", "=");
    if (ptr == NULL)
        goto exit;
    else {
        noise = atoi(ptr);
        if (stats != NULL )stats->sta_Noise = noise; 
    }
    
    ptr = ptr + strlen(ptr) + 1;
    ptr = parse_token(ptr, "level", "=");
    
    if (ptr == NULL)
        goto exit;
    else {
        rssi = atoi(ptr);
        if (stats != NULL )stats->sta_RSSI = rssi; 
    }
    ptr = ptr + strlen(ptr) + 1;
    
    ptr = parse_token(ptr, "est_throughput", "=");
    if (ptr == NULL)
        goto exit;
    else {
        phyrate = atoi(ptr);
        if (stats != NULL )stats->sta_PhyRate = phyrate; 
    }    
    
exit:
    wifi_hal_msg("bssid=%s, ssid=%s,  noise=%d, rssi=%d, phyrate=%d\n", bssid, ssid, noise, rssi, phyrate);
    G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
    return;
}


/**************************************************************************************************/
/*WIFI WPS Related Functions                                                                      */
/**************************************************************************************************/

INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool){
    UNUSED_VAR(ssidIndex);
    return RETURN_OK;
}

INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue){
    UNUSED_VAR(ssidIndex);
    return RETURN_OK;
}

INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong){ //Where does the PIN come from?
    UNUSED_VAR(ssidIndex);
    return RETURN_OK;
}

INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin){
    UNUSED_VAR(ssidIndex);
    wifi_hal_msg("Not Implemented / Error setting the device pin\n");
    return RETURN_ERR;
}

INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods){
    UNUSED_VAR(ssidIndex);
 
    if (!NULL_STRING(methods)){
        strcpy(methods, "Push and Pin");
        wifi_hal_msg("Supported Methods: Push and Pin\n");
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string){
  
    UNUSED_VAR(ssidIndex);
    if (!NULL_STRING(output_string)){
        strcpy(output_string, "Push and Pull");
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_setCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *methodString){
    UNUSED_VAR(ssidIndex);
    if (!NULL_STRING(methodString)){
        strcpy(methodString, "Push and Pin");
        wifi_hal_msg("Supported Methods: Push and Pin\n");
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string){
    UNUSED_VAR(ssidIndex);
    return RETURN_OK;
}

INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *EnrolleePin){
    UNUSED_VAR(ssidIndex);
    wifi_hal_msg("Not Implemented / Error setting Wps Pin\n");
    return RETURN_ERR;
}

INT wifi_setCliWpsButtonPush(INT ssidIndex){
  UNUSED_VAR(ssidIndex);
  char result[64];

  wifi_hal_msg("WPS Push Button Call\n");

  int ret=0;
  G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
  if(ret==-EBUSY) return -1;

  g_wifi.persist_ssid_enabled=1;
  send_wpa_cli_command(result, sizeof(result)-1, "REMOVE_NETWORK 0");
  send_wpa_cli_command(result, sizeof(result)-1, "SAVE_CONFIG");
  g_wifi.update_ssid_info=1;
 
  send_wpa_cli_command(result, sizeof(result)-1, "WPS_PBC");
  G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);

  wifi_hal_msg("Will be timing out if AP not found after 120 seconds\n");
  wifi_hal_msg("Deleting conf file and making a new one\n");

  /*factory_reset=1 will overwrite the existing configuration*/
  update_wpa_configuration(1, DISABLE_MEM_PSK, ENABLE_CONFIG_UPDATE);

  wifiStatusCode_t connStatus;
  connStatus = WIFI_HAL_CONNECTING;
  (*callback_connect)(1, "", &connStatus);
  wifi_hal_msg("Connection in progress..\n");
   
  wifi_hal_msg("WPS Push sent successfully\n");
  return RETURN_OK;
}

INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int saveSSID,CHAR * eapIdentity,CHAR * carootcert,CHAR * clientcert,CHAR * privatekey){

  UNUSED_VAR(ssidIndex);
  char result[64];
  wifi_hal_msg("Saving SSID to configuration file: %s\n", (saveSSID==0)?"Disabled":"Enabled");
  
  if(saveSSID) g_wifi.persist_ssid_enabled = 1;
  else         g_wifi.persist_ssid_enabled = 0;
  
  int ret=0;
  G_WIFI_MUTEX_TIMEDLOCK(&g_wifi.sup_lock, ret);
  if(ret==-EBUSY) return -1;

  wifi_hal_msg("Requesting connection with AP:%s, PSK=%s, Security mode:%d\n", AP_SSID, AP_security_PreSharedKey, AP_security_mode);
   
  send_wpa_cli_command(result, sizeof(result)-1, "REMOVE_NETWORK 0");
  send_wpa_cli_command(result, sizeof(result)-1, "ADD_NETWORK");
  send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 auth_alg OPEN");
  
  /* Set SSID */
  send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 ssid \"%s\"", AP_SSID);
  
  if(	(AP_security_mode == WIFI_SECURITY_WPA_PSK_AES)  || \
	(AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES) || \
	(AP_security_mode == WIFI_SECURITY_WPA_PSK_TKIP) || \
	(AP_security_mode == WIFI_SECURITY_WPA2_PSK_TKIP) ) {
      wifi_hal_msg("Security mode is PSK\n");
      /* Key Management */
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 key_mgmt WPA-PSK");
      /* Set the PSK */
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 psk \"%s\"", AP_security_PreSharedKey);
      if(strstr(result, "FAIL") != NULL){
          wifi_hal_msg("Password may not be falling within spec\n");
          wifiStatusCode_t connStatus;
          connStatus = WIFI_HAL_ERROR_INVALID_CREDENTIALS;
          (*callback_connect)(1, AP_SSID, &connStatus);
          G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
          return RETURN_ERR;
      }
  }
  else if((AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || \
	(AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES)    || \
	(AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP)  || \
	(AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES) ) {
      wifi_hal_msg("Security mode is WPA Enterprise\n");
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 key_mgmt WPA-EAP");
  }
  else{
      wifi_hal_msg("None\n");
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 key_mgmt NONE");
  }
  
  /* Allow us to connect to hidden SSIDs */
  send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 scan_ssid 1");
      
  if(	(AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || \
	(AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES)  || \
	(AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP)|| \
	(AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES) || \
	(AP_security_mode == WIFI_SECURITY_WPA_PSK_AES)         || \
	(AP_security_mode == WIFI_SECURITY_WPA2_PSK_AES) ) {
      wifi_hal_msg("Setting TKIP values\n");
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 pairwise CCMP TKIP");
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 group CCMP TKIP");
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 proto WPA RSN");
  }
  
  if(	(AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_TKIP) || \
	(AP_security_mode == WIFI_SECURITY_WPA_ENTERPRISE_AES)  || \
	(AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_TKIP)|| \
	(AP_security_mode == WIFI_SECURITY_WPA2_ENTERPRISE_AES) ) {
      wifi_hal_msg("EAP Identity %s\n", eapIdentity);
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 identity \"%s\"", eapIdentity);
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 eap TLS");
  }
  
  /* EAP with certificates */
  if (access(carootcert, F_OK) != -1){
      wifi_hal_msg("CA Root certificate [%s]\n", carootcert);
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 ca_cert \"%s\"", carootcert);
  }

  if (access(clientcert, F_OK) != -1){
      wifi_hal_msg("Client Certificate [%s]\n",clientcert);
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 client_cert \"%s\"", clientcert);
  }

  if (access(privatekey, F_OK) != -1){
      wifi_hal_msg("Private Key [%s]\n",privatekey);
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 private_key \"%s\"", privatekey);
      send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 private_key_passwd \"%s\"", AP_security_KeyPassphrase);
  }
  
  send_wpa_cli_command(result, sizeof(result)-1, "SET_NETWORK 0 mode 0");
  send_wpa_cli_command(result, sizeof(result)-1, "SELECT_NETWORK 0");
  send_wpa_cli_command(result, sizeof(result)-1, "ENABLE_NETWORK 0");
  send_wpa_cli_command(result, sizeof(result)-1, "REASSOCIATE");
  
  if(saveSSID){
    wifi_hal_msg("Connecting to the specified access point\n");
    wifiStatusCode_t connStatus;
    connStatus = WIFI_HAL_CONNECTING;
    if (callback_connect) (*callback_connect)(1, AP_SSID, &connStatus);
  }

  G_WIFI_MUTEX_UNLOCK(&g_wifi.sup_lock);
  return RETURN_OK;
}

INT wifi_lastConnected_Endpoint(wifi_pairedSSIDInfo_t *pairedSSIDInfo)
{
    char buf[512];
    char *tokenKey;
    char *tokenValue;
    static wifi_pairedSSIDInfo_t last_paired;
    static int last_conn_valid=0;

    if(!pairedSSIDInfo) return RETURN_ERR;
    if(!g_wifi.update_ssid_info && last_conn_valid) {
        memcpy(pairedSSIDInfo, &last_paired, sizeof(wifi_pairedSSIDInfo_t));
        return RETURN_OK;
    }

    FILE *f = fopen(WPA_SUPL_CONF, "r");
    if(f) {
        while( fgets(buf, 512, f) != NULL) {
            if(buf[0]=='\n') continue;
            else if(buf[strlen(buf)-1]=='\n') buf[strlen(buf)-1]='\0';

            tokenKey=strtok(buf,"\"=");
            tokenValue=strtok(NULL,"\"=");
            if(!tokenValue) continue;

            trimSpace(tokenKey);
            if(strcasecmp(tokenKey,"ssid") == 0) {
               strcpy(last_paired.ap_ssid,tokenValue);
               last_conn_valid=1;
            }
            else if(strcasecmp(tokenKey,"bssid") == 0) {
                strcpy(last_paired.ap_bssid,tokenValue);
            }
            else if(strcasecmp(tokenKey,"key_mgmt") == 0) {
               strcpy(last_paired.ap_security,tokenValue);
            }
           if(last_conn_valid){
               memcpy(pairedSSIDInfo, &last_paired, sizeof(wifi_pairedSSIDInfo_t));
               g_wifi.update_ssid_info=0;
           }
        }
        fclose(f);
    }
    if(!last_conn_valid) return RETURN_ERR;
    return RETURN_OK;
}

INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID){
   UNUSED_VAR(ssidIndex);
   char result[64];

   wifi_hal_msg("Received request to disconnect from AP\n");
   send_wpa_cli_command(result, sizeof(result)-1, "DISCONNECT");
   return RETURN_OK;
}
#endif

void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc){
  wifi_hal_msg("Registering connect callback.\n");
  callback_connect=callback_proc;

}

void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc){
   wifi_hal_msg("Registering disconnect callback.\n");
   callback_disconnect=callback_proc;
}

// Clear SSID info from HAL
INT wifi_clearSSIDInfo(INT ssidIndex) {
    char result[64];

    G_WIFI_MUTEX_LOCK(&g_wifi.sup_lock);
    send_wpa_cli_command(result, sizeof(result)-1, "REMOVE_NETWORK 0");
    send_wpa_cli_command(result, sizeof(result)-1, "SAVE_CONFIG");
    return RETURN_OK;
}

INT wifi_getDualBandSupport() {
    return RETURN_OK;

}

INT wifi_cancelWpsPairing() {
    return RETURN_OK;
}
