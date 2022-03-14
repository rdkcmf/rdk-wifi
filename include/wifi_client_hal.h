/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
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

/**********************************************************************

    module: wifi_client_hal.h

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------


    description:

        This header file gives the function call prototypes and
        structure definitions used for the RDK-Broadband
        Wifi client hardware abstraction layer

        NOTE:
        THIS VERSION IS AN EARLY DRAFT INTENDED TO GET COMMENTS FROM COMCAST.
        TESTING HAS NOT YET BEEN COMPLETED.

    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support Wifi drivers
        through an open API.

    ---------------------------------------------------------------

    author:

        zhicheng_qiu@cable.comcast.com


**********************************************************************/


#ifndef __WIFI_CLINET_HAL_H__
#define __WIFI_CLINET_HAL_H__

/**
 * @defgroup WIFI_HAL Wi-Fi HAL Public APIs and Data Types
 * @ingroup WIFI
 *
 * @defgroup WIFI_HAL_CLIENT_API Wi-Fi Client HAL API List
 * Wi-Fi Client HAL provides an interface (data structures and API) to interact with underlying Wi-Fi driver and
 * enabling the client to be connected with an Access Point.
 * @ingroup WIFI_HAL
 *
 */

#include <wifi_common_hal.h>
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint //EndPoint list is mananged by RDKB wifi agent
//Device.WiFi.EndPoint.{i}.Enable
//Device.WiFi.EndPoint.{i}.Status
//Device.WiFi.EndPoint.{i}.Alias
//Device.WiFi.EndPoint.{i}.ProfileReference
//Device.WiFi.EndPoint.{i}.SSIDReference
//Device.WiFi.EndPoint.{i}.ProfileNumberOfEntries
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Stats.LastDataDownlinkRate
//Device.WiFi.EndPoint.{i}.Stats.LastDataUplinkRate
//Device.WiFi.EndPoint.{i}.Stats.SignalStrength
//Device.WiFi.EndPoint.{i}.Stats.Retransmissions
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Security
//Device.WiFi.EndPoint.{i}.Security.ModesSupported
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Profile
//Device.WiFi.EndPoint.{i}.Profile.{i}.Enable
//Device.WiFi.EndPoint.{i}.Profile.{i}.Status
//Device.WiFi.EndPoint.{i}.Profile.{i}.Alias
//Device.WiFi.EndPoint.{i}.Profile.{i}.SSID
//Device.WiFi.EndPoint.{i}.Profile.{i}.Location
//Device.WiFi.EndPoint.{i}.Profile.{i}.Priority
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.ModeEnabled
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.WEPKey
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.PreSharedKey
//Device.WiFi.EndPoint.{i}.Profile.{i}.Security.KeyPassphrase
//----------------------------------------------------------------------------------------------------
//Device.WiFi.EndPoint.{i}.WPS
//Device.WiFi.EndPoint.{i}.WPS.Enable
//Device.WiFi.EndPoint.{i}.WPS.ConfigMethodsSupported
//Device.WiFi.EndPoint.{i}.WPS.ConfigMethodsEnabled

//-----------------------------------------------------------------------------------------------------
//AP connection APIs

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */

/**
 * @brief SSID information
 *
 * Structure which saves the paired SSID information.
 */
typedef struct _wifi_pairedSSIDInfo
{
  CHAR  ap_ssid[64];	//!< The current service set identifier in use by the neighboring WiFi SSID. The value MAY be empty for hidden SSIDs.
  CHAR  ap_bssid[64];	//!< [MACAddress] The BSSID (Basic Service Set ID) used for the neighboring WiFi SSID.
  CHAR  ap_security[64];	//!< Security of AP
  CHAR  ap_passphrase[128]; //!< Passphrase of AP
  CHAR  ap_wep_key[128]; //!< wep_key of AP incase of WEP security
}wifi_pairedSSIDInfo_t;

/**@} */

/**
 *  @brief Roaming Control information (pre assoc data structure}
 *
 *  Structure which saves pre association information.
 */
typedef struct _wifi_roamingCtrl_t
{
  BOOL roamingEnable;
  BOOL selfSteerOverride;
  BOOL roam80211kvrEnable;
  INT preassnBestThreshold;
  INT preassnBestDelta;
  INT postAssnLevelDeltaConnected;
  INT postAssnLevelDeltaDisconnected;
  INT postAssnSelfSteerThreshold;
  INT postAssnSelfSteerTimeframe;
  INT postAssnBackOffTime;
  //INT postAssnSelfSteerBeaconsMissedTime;
  INT postAssnAPctrlThreshold;
  INT postAssnAPctrlTimeframe;
  
}wifi_roamingCtrl_t;

/** @} */


//1. WPS method

/**
 * @addtogroup WIFI_HAL_CLIENT_API
 * @{
 */

/**
 * @brief This API checks WPS(Wi-Fi Protected Setup) functionality is enabled for this access point.
 *
 * @param[in]  ssidIndex The index of the SSID array.
 * @param[out] output_bool Boolean value which indicates the wps enabled status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_getCliWpsEnable(INT ssidIndex, BOOL *output_bool);	//RDKB

/**
 * @brief This API enables or disables WPS functionality for this access point.
 *
 * @param[in] ssidIndex The index of the SSID array.
 * @param[in] enableValue  Boolean value to enable or disable WPS.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_setCliWpsEnable(INT ssidIndex, BOOL enableValue);	//RDKB

/**
 * @brief This API is used to read the device PIN required for making a WPS connection.
 *
 * @param[in] ssidIndex The index of the SSID array.
 * @param[out] output_ulong  Output parameter which saves the Device PIN.
 * This value is to be printed on the device.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_getCliWpsDevicePIN(INT ssidIndex, ULONG *output_ulong);	//RDKB

/**
 * @brief This API sets the WPS Device pin to the Wi-Fi hal.
 *
 * @param[in] ssidIndex The index of the SSID array.
 * @param[in] pin The PIN code to set.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_setCliWpsDevicePIN(INT ssidIndex, ULONG pin);	//RDKB

/**
 * @brief This API is used to get WPS configuration  methods supported by the device.
 *
 * This function provides the comma-separated list of strings, each list item is an enumeration of:
 * - USBFlashDrive - User uses a USB flash drive to transfer data between the new client device and
 * the network's access point.
 * - Ethernet - If there is no WPS button, user can configure the wireless settings using ethernet on a wifi-extender
 * - ExternalNFCToken - NFC Tag contains a password token to authenticate Wi-Fi connection.
 * Uses external program to write  * NDEF encapsulation data to the NFC tag using an external program.
 * - IntegratedNFCToken - The NFC Tag is integrated in the device.
 * - NFCInterface - User has to bring the client close to AP allowing a near field communication between the devices.
 * - PushButton - User has to push a button, either an actual or virtual one,
 * on both the access point and the new wireless * client device.
 * - PIN - User has to be read the PIN from either a sticker or display on the new wireless device.
 *
 * Device must support PushButton and PIN methods.
 *
 * @param[in]  ssidIndex The index of SSID array.
 * @param[out] methods  The WPS supported methods.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_getCliWpsConfigMethodsSupported(INT ssidIndex, CHAR *methods);		//OEM

/**
 * @brief This function indicates WPS configuration methods enabled on the device.
 *
 * The API provides the comma-separated list of strings.
 * Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter.
 *
 * @param[in]  ssidIndex The index of SSID array.
 * @param[out] output_string  The current WPS method.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_getCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *output_string);	//RDKB

/**
 * @brief This API sets the active WPS method.
 *
 * @param[in] ssidIndex The index of SSID array.
 * @param[in] methodString The method to enable.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_setCliWpsConfigMethodsEnabled(INT ssidIndex, CHAR *methodString);	//RDKB

/**
 * @brief This API is used to get the WPS config status, whether "configured" or "not configured"
 *
 * @param[in] ssidIndex The index of SSID array
 * @param[in] output_string  The output paramter which holds the wps config status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_getCliWpsConfigurationState(INT ssidIndex, CHAR *output_string);	//RDKB	//OEM

/**
 * @brief This API sets the PIN to connect.
 * User get the EnrolleePin (device pin from AP device) give to hostapd for pairing.
 *
 * @param[in] ssidIndex The index of SSID array.
 * @param[in] EnrolleePin PIN code to connect to the access point.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_setCliWpsEnrolleePin(INT ssidIndex, CHAR *EnrolleePin);	//RDKB

/**
 * @brief Start the Push button pairing.
 *
 * @param[in] ssidIndex The index of SSID array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_setCliWpsButtonPush(INT ssidIndex);	//RDKB

/**
 * @brief Stop the WPS process.
 *
 * @param[in] ssidIndex The index of SSID array.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_cancelCliWPS(INT ssidIndex);	//RDKB


//2. Directly pairing method
/**
 * @brief This API starts the connection process from client with an AP.
 *
 * It uses the input parameters to connect using a supported security method and encryption standard.
 * The security methods can make use of passphrase, public/private key pairs etc.
 *
 * @param[in] ssidIndex The index of SSID array.
 * @param[in] AP_SSID  The ssid to connect.
 * @param[in] AP_security_mode   The security mode to use.
 * @param[in] AP_security_WEPKey The wep key.
 * @param[in] AP_security_PreSharedKey The pre shared key.
 * @param[in] AP_security_KeyPassphrase The key passphrase.
 * @param[in] saveSSID Option to save profile in wpa supplicant.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_connectEndpoint(INT ssidIndex, CHAR *AP_SSID, wifiSecurityMode_t AP_security_mode, CHAR *AP_security_WEPKey, CHAR *AP_security_PreSharedKey, CHAR *AP_security_KeyPassphrase,int saveSSID,CHAR * eapIdentity,CHAR * carootcert,CHAR * clientcert,CHAR * privatekey);	//Tr181

/**
 * @brief This API disconnects the access point specified.
 *
 * @param[in] ssidIndex The index of SSID array.
 * @param[in] AP_SSID  The ssid to disconnect.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_disconnectEndpoint(INT ssidIndex, CHAR *AP_SSID);

// Clear SSID information
INT wifi_clearSSIDInfo(INT ssidIndex);

/**
 * @brief This call back should be registered by Wi-Fi manager to receive status updates from HAL in case of a
 * connection/disconnection event.
 *
 * @param[in]  ssidIndex The index of SSID array.
 * @param[in]  AP_SSID  The ssid to disconnect.
 * @param[out] error Indicates the Wi-Fi connection sttaus.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
typedef INT (*wifi_disconnectEndpoint_callback)(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error);

/**
 * @brief Callback registration function.
 *
 * @param[in] callback_proc the callback function to disconnect the client.
 */
void wifi_disconnectEndpoint_callback_register(wifi_disconnectEndpoint_callback callback_proc);

/**
 * @brief This call back will be invoked when client automatically connect to Access Point.
 *
 * @param[in]  ssidIndex The index of SSID array.
 * @param[in]  AP_SSID  The ssid to disconnect.
 * @param[out] error Indicates the Wi-Fi connection status.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
typedef INT (*wifi_connectEndpoint_callback)(INT ssidIndex, CHAR *AP_SSID, wifiStatusCode_t *error);

/**
 * @brief Callback registration function.
 *
 * @param[in] callback_proc The callback function to connect the client to the access point.
 */
void wifi_connectEndpoint_callback_register(wifi_connectEndpoint_callback callback_proc);

/**
 * @brief This call will give the last saved AP's ssid.
 *
 * @param[out] pairedSSIDInfo Structure which holds the last connected access point information.
 *
 * @return The status of the operation.
 * @retval RETURN_OK returns O if successful, appropriate error code otherwise.
 */
INT wifi_lastConnected_Endpoint(wifi_pairedSSIDInfo_t *pairedSSIDInfo);
/** @} */


/**
 * @brief this call will set the Roaming control data for a client
 *
 * @param[in] ssidIndex, this is used to validate the ssid
 * @param[in] pRoamingCtrl_data, this is the structure with values to be set
 *
 * @returns SET status of the pRoamingCtrl data
 * @retval 0 if SUCCESFULLY sets the values
 */
int wifi_setRoamingControl (int ssidIndex, wifi_roamingCtrl_t *pRoamingCtrl_data);
/** @} */

/**
 * @brief this call gets the Roaming control data
 *
 * @param[in] ssidIndex to validate the interface
 * @param[out] pRoamingCtrl_data
 *
 * @returns GET status
 * @retval 0 if SUCCESSFULLY gets the Roaming control data
 */
int wifi_getRoamingControl(int ssidIndex, wifi_roamingCtrl_t *pRoamingCtrl_data);

/**
 * @brief this call gets the current wifi status
 *
 * @returns wifi_status_code
 */
WiFiHalStatus_t getwifiStatusCode();

/**
 * @brief this call will cancel any in progress WPS operaiotn
 *
 * @returns WPS cancel status.
 * @retval 0 if SUCCESFULLY cancels WPS operation, false in failure cases.
 */
INT wifi_cancelWpsPairing();

/** @} */
#else
#error "! __WIFI_CLINET_HAL_H__"
#endif
