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
#include <malloc.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctype.h>
#include "wifi_client_hal.h"

#define INVALID_INPUT -99
#define TIME_WAIT 40
#define MAX_FILE_PATH_LEN 4096

typedef enum _input_types {
    type_int=0,
    type_string=1,
    type_char=2
}INPUT_TYPES_E;

void ut_wifi_getStats(void);
void ut_wifi_getNeighboringWiFiDiagnosticResult(void);
void ut_wifi_setCliWpsButtonPush(int waitTime);
INT ut_wifi_connect_callback(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error);
INT ut_wifi_disconnect_callback(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error);
INT ut_wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID,CHAR *AP_security_KeyPassphrase, \
		wifiSecurityMode_t AP_security_mode,CHAR *eapIdentity,CHAR *carootcert,CHAR *clientcert,CHAR *privatekey);
void ut_wifi_getRadioMaxBitRate(void);
void ut_wifi_disconnectEndpoint(char *,int );
void ut_wifi_init(void);
void ut_wifi_getRadioTrafficStats(void);
void ut_wifi_lastConnected_Endpoint(void);
void ut_wifi_factoryReset(void);

void help(void);

pthread_mutex_t connMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t connCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t disconMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t disconCond = PTHREAD_COND_INITIALIZER;
int wpsWaitTime;
int disconnectWaitTime;
int init_done=0;
int check;
int connectFlag;
int disconnectFlag;
pthread_t connectThread=NULL;

void exit_handler(int sig)
{
    //if(init_done==1)
        //wifi_uninit();
    exit(0);
}
#define INPUT_NUMBER(var, ...) get_input_string(type_int,    var, __VA_ARGS__)
#define INPUT_STRING(var, ...) get_input_string(type_string, var, __VA_ARGS__)
#define INPUT_CHAR(var, ...)   get_input_string(type_char,   var, __VA_ARGS__)
void get_input_string(INPUT_TYPES_E var_type, void *input, const char *prompt, ...)
{
   #define MAX_INPUT 100
   va_list argp;
   char buf[MAX_INPUT];
   va_start(argp, prompt);
   vprintf(prompt, argp);
   va_end(argp);

   fgets(buf, MAX_INPUT, stdin);
   if(var_type==type_int) {
       if(isdigit(buf[0]))
           sscanf(buf,"%d",(int*)input);
       else
           *(int*)input=-1;
   }
   else if(var_type==type_string) {
       sscanf(buf,"%[^\n]",(char*)input);
   }
   else if(var_type==type_char) {
       sscanf(buf,"%c",(char*)input);
   }
   /*add more cases if required...*/
   return;
}


void help()
{
    printf("\n****************** WiFi HAL Basic API Test Options ******************\n");
    printf(" [ 1 ]    Wifi init			 \n");
    printf(" [ 2 ]    Press wps button 		 \n");
    printf(" [ 3 ]    Connect to ssid 		 \n");
    printf(" [ 4 ]    Disconnect from ssid	 \n");
    printf(" [ 5 ]    SSID statistics            \n");
    printf(" [ 6 ]    SCAN All SSID              \n");
    printf(" [ 7 ]    Get traffic statistics     \n");
    printf(" [ 8 ]    Get Last connected SSID    \n");
    printf(" [ 9 ]    Get Max bit rate           \n");
    printf(" [ 10 ]   Wifi factory reset         \n");
    printf(" [ h ]    Show this list             \n");
    printf(" [ q ]    Quit	 		 \n");
    printf("***********************************************************************\n");
}

void ut_wifi_init()
{
    if(wifi_init() == RETURN_OK) {
        init_done=1;
        printf("\n WiFi intialize success  \n ");
    }
    else {
        printf("\n WiFi Intialization failure \n ");
    }
    return;
}

void ut_wifi_getNeighboringWiFiDiagnosticResult(void)
{
    wifi_neighbor_ap_t *neighborAPlist=NULL, *element;
    UINT items_found=0;
    UINT idx;
    if(wifi_getNeighboringWiFiDiagnosticResult(1,&neighborAPlist,&items_found)==RETURN_ERR) {
       printf("Failed on ut_wifi_getNeighboringWiFiDiagnosticResult()\n");
       return;
    }
    printf("\n////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
    printf("[STAT] %-26s %-20s %-26s %-12s %-s","SSID: ","BSSID","EncryptionMode:","Frequency:","Signal:");
    printf("\n////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
    for(idx=0; idx < items_found; idx++)
    {
        element=&neighborAPlist[idx];
        if( element->ap_SignalStrength > -50)
            printf("[EXCL]");
        else if(( element->ap_SignalStrength <= -50) && ( element->ap_SignalStrength > -60) )
            printf("[GOOD]");
        else if(( element->ap_SignalStrength <= -60) && (element->ap_SignalStrength > -70) )
            printf("[FAIR]");
        else if( element->ap_SignalStrength <= -70)
            printf("[POOR]");
        printf(" [%-24s] [%18s] [%-24s] [%-5s] [%d]\n", element->ap_SSID, element->ap_BSSID,\
		element->ap_EncryptionMode, element->ap_OperatingFrequencyBand, element->ap_SignalStrength);
    }
    printf("////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
    free(neighborAPlist);
    return;
}

void *connThreadFunc(void* arg)
{
    struct timespec waitTime;
    struct timeval now;
    int ret;

    ret =  gettimeofday(&now, NULL);

    waitTime.tv_sec  = now.tv_sec;
    waitTime.tv_nsec = now.tv_usec * 1000;
    waitTime.tv_sec += wpsWaitTime;

    pthread_mutex_lock(&connMutex);
    ret=0;
    while (!connectFlag && ret != ETIMEDOUT)
    {
        ret = pthread_cond_timedwait(&connCond, &connMutex, &waitTime);
    }
    if (ret == ETIMEDOUT)
    {
        check=1;
        printf("timed out connecting to AP \n");
    }
    connectFlag=0;
    ret = pthread_mutex_unlock(&connMutex);
    pthread_exit(NULL);
}

void *disconnectThreadFunc(void* arg)
{
    struct timespec waitTime;
    struct timeval now;
    int ret;

    ret =  gettimeofday(&now, NULL);

    waitTime.tv_sec  = now.tv_sec;
    waitTime.tv_nsec = now.tv_usec * 1000;
    waitTime.tv_sec += disconnectWaitTime;

    pthread_mutex_lock(&disconMutex);
    ret=0;
    while (!disconnectFlag && ret != ETIMEDOUT)
    {
        ret = pthread_cond_timedwait(&disconCond, &disconMutex, &waitTime);
    }
    if (ret == ETIMEDOUT)
    {
        check=1;
        printf("timed out connecting to AP \n");
    }
    disconnectFlag=0;
    ret = pthread_mutex_unlock(&disconMutex);

    pthread_exit(NULL);
}

INT ut_wifi_disconnect_callback(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error)
{
    pthread_mutex_lock(&disconMutex);
    disconnectFlag=1;
    pthread_cond_broadcast(&disconCond);
    pthread_mutex_unlock(&disconMutex);
    if(*error == WIFI_HAL_SUCCESS)
    {
        printf("disconnected from %s \n ", AP_SSID);
        return RETURN_OK;
    }
    printf("disonnection error %d to ssid %s  \n ",*error,AP_SSID);
    return RETURN_ERR;
//    pthread_exit(NULL);
}


INT ut_wifi_connect_callback(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error)
{
    pthread_mutex_lock(&connMutex);
    connectFlag=1;
    pthread_cond_broadcast(&connCond);
    pthread_mutex_unlock(&connMutex);
    if(*error == WIFI_HAL_SUCCESS)
    {
        printf("Connected to %s \n ", AP_SSID);
        return RETURN_OK;
    }
    printf("Connection error %d to %s  \n ",*error,AP_SSID);
    return RETURN_ERR;
//    pthread_exit(NULL);
}

void ut_wifi_setCliWpsButtonPush(int waitTime)
{
    void *ret;

    wpsWaitTime=waitTime;
//    pthread_join(wpsThread,&ret);
    if(wifi_setCliWpsButtonPush(1) == RETURN_OK)
    {
        printf("\n WPS push button press success \n ");
    }
    else
    {
        printf("\n WPS button press failed \n ");
        return;
    }
    if(connectThread == NULL)
    {
        pthread_create(&connectThread, NULL,connThreadFunc, NULL);
        pthread_join(connectThread,&ret);
        connectThread = NULL;
    }
    else
        printf("connecting to AP is going on please try after sometime \n");
}

INT ut_wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID,CHAR *AP_security_KeyPassphrase,wifiSecurityMode_t AP_security_mode,CHAR *eapIdentity,CHAR *carootcert,CHAR *clientcert,CHAR *privatekey)
{
    int ret;
    int saveSSID=1;
    wpsWaitTime=TIME_WAIT;
    ret=wifi_connectEndpoint(ssidIndex,AP_SSID,AP_security_mode,NULL,AP_security_KeyPassphrase,NULL,saveSSID,eapIdentity,carootcert,clientcert,privatekey);
    if(ret) {
        printf("Error in connecting to ssid %s  with passphrase %s \n",AP_SSID,AP_security_KeyPassphrase);
    }
    else {
        printf("connecting to ssid %s  with passphrase %s \n",AP_SSID,AP_security_KeyPassphrase);
    }
    if(connectThread == NULL) {
        pthread_create(&connectThread, NULL,connThreadFunc, NULL);
        pthread_join(connectThread, NULL);
        connectThread = NULL;
    }
    else
        printf("connecting to AP is going on please try after sometime \n");
}

void ut_wifi_disconnectEndpoint(char* ssid,int waitTime)
{

    pthread_t disconnectThread;
    void *ret;
    disconnectWaitTime=waitTime;
    pthread_create(&disconnectThread, NULL,disconnectThreadFunc, NULL);
    wifi_disconnectEndpoint(1, ssid);
}

void ut_wifi_getStats()
{
    wifi_getStats(1, NULL);
}

void ut_wifi_getRadioTrafficStats(void) {
    wifi_radioTrafficStats_t stat;
    if(wifi_getRadioTrafficStats(1, &stat) == RETURN_OK) {
        printf("Traffic Statistics: TX [Bytes: %u, PKT: %u, Err: %u, Drop: %u] RX[Bytes: %u, PKT: %u, Err: %u, Drop: %u]\n",\
	stat.radio_BytesSent, stat.radio_PacketsSent, stat.radio_ErrorsSent, stat.radio_DiscardPacketsSent,\
	stat.radio_BytesReceived, stat.radio_PacketsReceived, stat.radio_ErrorsReceived, stat.radio_DiscardPacketsReceived);
    }
    else printf("failed to receive traffic statistics on wlan0\n");
    return;
}
void ut_wifi_getRadioMaxBitRate(void) {
    char output[16];
    if(wifi_getRadioMaxBitRate(1, output) == RETURN_OK)
        printf("Max bit rate supported: %s\n",output);
    else printf("Failed to get max bit rate information\n");
    return;
}
void ut_wifi_lastConnected_Endpoint(void){
   wifi_pairedSSIDInfo_t last_ssid;
   memset(&last_ssid, 0, sizeof(last_ssid));
   if(wifi_lastConnected_Endpoint(&last_ssid)==RETURN_OK) {
      printf("Last connected [SSID: %s, BSSID:%s, Security:%s]\n",last_ssid.ap_ssid, last_ssid.ap_bssid, last_ssid.ap_security);
   }
   else printf("Failed to retrieve last connected SSID information\n");
   return;
}

void ut_wifi_factoryReset(void){
    if(wifi_factoryReset()==RETURN_OK)
       printf("Wifi factory reset done.\n");
    else
       printf("Wifi factory reset failed.\n");
}

int main(int argc, char * argv[])
{
#define MAX_TEST_CASE 10
    char input[16];
    int timeoutWps;
    int select;
    char ssid[80];
    wifiSecurityMode_t securityMode;
    char keyPassphrase[80];
    char eapIdentity[80];
    char carootcert[MAX_FILE_PATH_LEN];
    char clientcert[MAX_FILE_PATH_LEN];
    char privatekey[MAX_FILE_PATH_LEN];
    int timeout;

    signal(SIGTERM, exit_handler);
    signal(SIGINT,  exit_handler);
    signal(SIGPIPE, exit_handler);

    wifi_connectEndpoint_callback_register(ut_wifi_connect_callback);
    wifi_disconnectEndpoint_callback_register(ut_wifi_disconnect_callback);
    help();
    while(1)
    {
        input[0]='\0';
        INPUT_STRING(&input,"\n[ Enter your choice ]: ");
        if(input[0] == 'h') {
            help();
            continue;
        }
        else if (input[0] == 'q') {
                exit_handler(0);
        }
        else {
           if(!isdigit(input[0])) select=INVALID_INPUT;
	   else select=atoi(input);
           if(select==INVALID_INPUT || select < 0 || select > MAX_TEST_CASE){
             printf("Entered option [%s] is not a valid one, supported are [h, q, 0-%d]\n",input,MAX_TEST_CASE);
             continue;
           }
        }
        if (0&&(select != 1) && (init_done != 1)) {
            printf("!!! Please Select 'WIFI INIT' Before using other options, Press 'h' For Help !!!\n");
            continue;
        }

        switch(select) {
        case 1:
            ut_wifi_init();
            break;
        case 2:
            INPUT_NUMBER(&timeoutWps, "[[ please enter timeout value for WPS ]] \n");
            ut_wifi_setCliWpsButtonPush(timeoutWps);
            break;
        case 3:
            INPUT_STRING(ssid, "[[ Please enter the SSID ]] \n");
            INPUT_NUMBER(&securityMode, "[[ Supported Security modes: ]] \n %s [[ Please enter security mode for SSID:%s] ",\
			"WIFI_SECURITY_WEP_64               0 \n\
			 WIFI_SECURITY_WEP_128              1 \n\
			 WIFI_SECURITY_WPA_PSK_TKIP         2 \n\
			 WIFI_SECURITY_WPA_PSK_AES          3 \n\
			 WIFI_SECURITY_WPA2_PSK_TKIP        4 \n\
			 WIFI_SECURITY_WPA2_PSK_AES         5 \n\
			 WIFI_SECURITY_WPA_ENTERPRISE_TKIP  6 \n\
			 WIFI_SECURITY_WPA_ENTERPRISE_AES   7 \n\
			 WIFI_SECURITY_WPA2_ENTERPRISE_TKIP 8 \n\
			 WIFI_SECURITY_WPA2_ENTERPRISE_AES  9 \n",ssid);
            if(!isalnum(ssid[0])) {printf("Invalid input [%s],[%d] for SSID,security\n",ssid,securityMode);continue;}
            if((securityMode >= WIFI_SECURITY_NONE ) && (securityMode < WIFI_SECURITY_WPA_PSK_TKIP ))
            {
                    INPUT_STRING(keyPassphrase, "[[ Please enter passphrase for SSID=%s ]] \n",ssid);
                    ut_wifi_connectEndpoint(1,ssid,keyPassphrase,securityMode,NULL,NULL,NULL,NULL);
            }
            else if((securityMode >= WIFI_SECURITY_WPA_PSK_TKIP ) && (securityMode < WIFI_SECURITY_WPA_ENTERPRISE_TKIP ))
            {
                    INPUT_STRING(keyPassphrase, "[[ Please enter PSK for SSID=%s ]] \n",ssid);
                    ut_wifi_connectEndpoint(1,ssid,keyPassphrase,securityMode,NULL,NULL,NULL,NULL);
                
            }
            else if((securityMode >= WIFI_SECURITY_WPA_ENTERPRISE_TKIP ) && (securityMode < WIFI_SECURITY_NOT_SUPPORTED))
            {
                    INPUT_STRING(keyPassphrase, "[[ Please enter pass-key for SSID=%s     ]] \n",ssid);
                    INPUT_STRING(eapIdentity,   "[[ Please enter EAP Identity for SSID=%s ]] \n",ssid);
                    INPUT_STRING(carootcert,    "[[ Please enter CA Root CERT for SSID=%s ]] \n",ssid);
                    INPUT_STRING(clientcert,    "[[ Please enter Client CERT for SSID=%s  ]] \n",ssid);
                    INPUT_STRING(privatekey,    "[[ Please enter Private Key for SSID=%s  ]] \n",ssid);
                    ut_wifi_connectEndpoint(1,ssid,keyPassphrase,securityMode,eapIdentity,carootcert,clientcert,privatekey);
                
            }
            else
            {
                printf("Security Mode %d Not Supported",securityMode);
                securityMode=WIFI_SECURITY_NONE;
            }
            break;
        case 4:
            INPUT_STRING(ssid, "[[ Please enter the SSID ]] \n");
            INPUT_NUMBER(&timeout, "Please enter timeout for disconnect\n");
            ut_wifi_disconnectEndpoint(ssid,timeout);
            break;

        case 5:
            printf("Print Current SSID Information [Shows result if connected]\n");
            ut_wifi_getStats();
            break;
        case 6:
            printf("Performing a SCAN on All SSID\n");
            ut_wifi_getNeighboringWiFiDiagnosticResult();
            break;
        case 7:
            printf("Getting traffic statistics\n");
            ut_wifi_getRadioTrafficStats();
            break;
        case 8:
            printf("Getting last connected SSID information\n");
            ut_wifi_lastConnected_Endpoint();
            break;
        case 9:
            printf("Getting Max Bit rate\n");
            ut_wifi_getRadioMaxBitRate();
            break;
        case 10:
            printf("Doing a wifi factory reset\n");
            ut_wifi_factoryReset();
            break;
        default:
            printf("Option [%d] not supported \n",select);
            continue;
        }
    }
}
