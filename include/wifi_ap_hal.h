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

    module: wifi_ap_hal.h

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and
        structure definitions used for the RDK-Broadband
        Wifi AP hardware abstraction layer

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
        Charles Moreman, moremac@cisco.com


**********************************************************************/

#ifndef __WIFI_AP_HAL_H__
#define __WIFI_AP_HAL_H__

#include <wifi_common_hal.h>

//Please do not edit the elements for this data structure
typedef struct _wifi_associated_dev
{
    //UCHAR cli_devMacAddress[6];
    //CHAR  cli_devIPAddress[64];
    //BOOL  cli_devAssociatedDeviceAuthentiationState;
    //INT   cli_devSignalStrength;
    //INT   cli_devTxRate;
    //INT   cli_devRxRate;

    UCHAR cli_MACAddress[6];		// The MAC address of an associated device.
    BOOL  cli_AuthenticationState; // Whether an associated device has authenticated (true) or not (false).
    UINT  cli_LastDataDownlinkRate; //The data transmit rate in kbps that was most recently used for transmission from the access point to the associated device.
    UINT  cli_LastDataUplinkRate; 	// The data transmit rate in kbps that was most recently used for transmission from the associated device to the access point.
    INT   cli_SignalStrength; 		//An indicator of radio signal strength of the uplink from the associated device to the access point, measured in dBm, as an average of the last 100 packets received from the device.
    UINT  cli_Retransmissions; 	//The number of packets that had to be re-transmitted, from the last 100 packets sent to the associated device. Multiple re-transmissions of the same packet count as one.
    BOOL  cli_Active; 				//	boolean	-	Whether or not this node is currently present in the WiFi AccessPoint network.

    CHAR  cli_OperatingStandard[64];	//Radio standard the associated Wi-Fi client device is operating under. Enumeration of:
    CHAR  cli_OperatingChannelBandwidth[64];	//The operating channel bandwidth of the associated device. The channel bandwidth (applicable to 802.11n and 802.11ac specifications only). Enumeration of:
    INT   cli_SNR;		//A signal-to-noise ratio (SNR) compares the level of the Wi-Fi signal to the level of background noise. Sources of noise can include microwave ovens, cordless phone, bluetooth devices, wireless video cameras, wireless game controllers, fluorescent lights and more. It is measured in decibels (dB).
    CHAR  cli_InterferenceSources[64]; //Wi-Fi operates in two frequency ranges (2.4 Ghz and 5 Ghz) which may become crowded other radio products which operate in the same ranges. This parameter reports the probable interference sources that this Wi-Fi access point may be observing. The value of this parameter is a comma seperated list of the following possible sources: eg: MicrowaveOven,CordlessPhone,BluetoothDevices,FluorescentLights,ContinuousWaves,Others
    ULONG cli_DataFramesSentAck;	//The DataFramesSentAck parameter indicates the total number of MSDU frames marked as duplicates and non duplicates acknowledged. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification.
    ULONG cli_DataFramesSentNoAck;	//The DataFramesSentNoAck parameter indicates the total number of MSDU frames retransmitted out of the interface (i.e., marked as duplicate and non-duplicate) and not acknowledged, but does not exclude those defined in the DataFramesLost parameter. The value of this counter may be reset to zero when the CPE is rebooted. Refer section A.2.3.14 of CableLabs Wi-Fi MGMT Specification.
    ULONG cli_BytesSent;	//The total number of bytes transmitted to the client device, including framing characters.
    ULONG cli_BytesReceived;	//The total number of bytes received from the client device, including framing characters.
    INT   cli_RSSI;	//The Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for transmissions from the device averaged over past 100 packets recevied from the device.
    INT   cli_MinRSSI;	//The Minimum Received Signal Strength Indicator, RSSI, parameter is the minimum energy observed at the antenna receiver for past transmissions (100 packets).
    INT   cli_MaxRSSI;	//The Maximum Received Signal Strength Indicator, RSSI, parameter is the energy observed at the antenna receiver for past transmissions (100 packets).
    UINT  cli_Disassociations;	//This parameter  represents the total number of client disassociations. Reset the parameter evey 24hrs or reboot
    UINT  cli_AuthenticationFailures;	//This parameter indicates the total number of authentication failures.  Reset the parameter evey 24hrs or reboot

} wifi_associated_dev_t;	//COSA_DML_WIFI_AP_ASSOC_DEVICE

typedef struct _wifi_radius_setting_t
{
    INT  RadiusServerRetries; 			//Number of retries for Radius requests.
    INT  RadiusServerRequestTimeout; 	//Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.
    INT  PMKLifetime; 					//Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).
    BOOL PMKCaching; 					//Enable or disable caching of PMK.
    INT  PMKCacheInterval; 			//Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).
    INT  MaxAuthenticationAttempts; 	//Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
    INT  BlacklistTableTimeout; 		//Time interval in seconds for which a client will continue to be blacklisted once it is marked so.
    INT  IdentityRequestRetryInterval; //Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.
    INT  QuietPeriodAfterFailedAuthentication;  //The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.
    UCHAR RadiusSecret[64];			//The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

} wifi_radius_setting_t;

//typedef struct wifi_AC_parameters_record  // Access Catagoriy parameters.  see 802.11-2012 spec for descriptions
//{
//     INT CWmin;       // CWmin variable
//     INT CWmax;       // CWmax vairable
//     INT AIFS;        // AIFS
//     ULONG TxOpLimit;  // TXOP Limit
//} wifi_AC_parameters_record_t;


//typedef struct _wifi_qos
//{
//     wifi_AC_parameters_record_t BE_AcParametersRecord;      // Best Effort QOS parameters, ACI == 0
//     wifi_AC_parameters_record_t BK_AcParametersRecord;      // Background QOS parameters, ACI == 1
//     wifi_AC_parameters_record_t VI_AcParametersRecord;      // Video QOS parameters, ACI == 2
//     wifi_AC_parameters_record_t VO_AcParametersRecord;      // Voice QOS parameters, ACI == 3
//}  wifi_qos_t;


//---------------------------------------------------------------------------------------------------
//
// Additional Wifi radio level APIs used for RDKB Access Point devices
//
//---------------------------------------------------------------------------------------------------

INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable);          //P3 // enables CTS protection for the radio used by this AP
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable);        // enables OBSS Coexistence - fall back to 20MHz if necessary for the radio used by this ap
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold);    //P3 // sets the fragmentation threshold in bytes for the radio used by this ap
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable);           // enable STBC mode in the hardwarwe, 0 == not enabled, 1 == enabled
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool);         // outputs A-MSDU enable status, 0 == not enabled, 1 == enabled
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable);          // enables A-MSDU in the hardware, 0 == not enabled, 1 == enabled
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int);           //P2  // outputs the number of Tx streams
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams);            //P2  // sets the number of Tx streams to an enviornment variable
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int);           //P2  // outputs the number of Rx streams
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams);            //P2  // sets the number of Rx streams to an enviornment variable
//INT wifi_pushRadioChannel(INT radioIndex, UINT channel);                 //P2  // push the channel number setting to the hardware  //Applying changes with wifi_applyRadioSettings().
//INT wifi_pushRadioChannelMode(INT radioIndex);                           //P2  // push the channel mode enviornment variable that is set by "wifi_setChannelMode()" to the hardware  //Applying changes with wifi_applyRadioSettings().
//INT wifi_pushRadioTxChainMask(INT radioIndex);                           //P2  // push the enviornment varible that is set by "wifi_setTxChainMask()" to the hardware //Applying changes with wifi_applyRadioSettings().
//INT wifi_pushRadioRxChainMask(INT radioIndex);                           //P2  // push the enviornment varible that is set by "wifi_setRxChainMask()" to the hardware //Applying changes with wifi_applyRadioSettings().

INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool);    //Get radio RDG enable setting
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable);			//Set radio RDG enable setting
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool);			//Get radio ADDBA enable setting
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable);				//Set radio ADDBA enable setting
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool);				//Get radio auto block ack enable setting
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable);					//Set radio auto block ack enable setting
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool);			//Get radio 11n pure mode enable setting
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable);					//Set radio 11n pure mode enable setting
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool);				//Get radio IGMP snooping enable setting
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable);					//Set radio IGMP snooping enable setting
INT wifi_getRadioDfsSupport(INT radioIndex, UINT *output_uint);						//Get radio DFS support
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool);						//Get radio DFS enable setting
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enabled);							//Set radio DFS enable setting
//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------


//AP HAL
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid);  // creates a new ap and pushes these parameters to the hardware
INT wifi_deleteAp(INT apIndex);                                     // deletes this ap entry on the hardware, clears all internal variables associaated with this ap
INT wifi_getApName(INT apIndex, CHAR *output_string);                 // Outputs a 16 byte or less name assocated with the AP.  String buffer must be pre-allocated by the caller

INT wifi_getApBeaconType(INT apIndex, CHAR *output_string);           // Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString);        // Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval);        // sets the beacon interval on the hardware for this AP
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold);              // sets the packet size threshold in bytes to apply RTS/CTS backoff rules.

INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string);    // ouputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode);          // sets the encyption mode enviornment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_removeApSecVaribles(INT apIndex);                            // deletes internal security varable settings for this ap
INT wifi_disableApEncryption(INT apIndex);                            // changes the hardware settings to disable encryption on this ap
INT wifi_setApAuthMode(INT apIndex, INT mode);                        // set the authorization mode on this ap
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode);   // sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"

INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac);  	// manually removes any active wi-fi association with the device specified on this ap

INT wifi_getApRadioIndex(INT apIndex, INT *output_int);                // outputs the radio index for the specified ap
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex);                // sets the radio index for the specific ap

INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress);         // adds the mac address to the filter list
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress);         // deletes the mac address from the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint);           // outputs the number of devices in the filter list
INT wifi_kickApAclAssociatedDevices(INT apIndex,BOOL enable);         // enable kick for devices on acl black list
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode);     // sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled);              // enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE.

INT wifi_setApVlanID(INT apIndex, INT vlanId);                        // sets the vlan ID for this ap to an internal enviornment variable
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet);	// gets bridgeName, IP address and Subnet.
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet);   //sets bridgeName, IP address and Subnet to internal enviornment variables. bridgeName is a maximum of 32 characters,
//INT wifi_pushApBridgeInfo(INT apIndex);                               // push the BridgeInfo enviornment variables to the hardware //Applying changes with wifi_applyRadioSettings()
INT wifi_resetApVlanCfg(INT apIndex);                                 // reset the vlan configuration for this ap
INT wifi_setApBridging(INT apIndex, BOOL bridgeEnable);             // set the enviornment variables to control briding.  If isolation is requried then disable bridging.
//INT wifi_getApRouterEnable(INT apIndex, BOOL *output_bool);           //P4 // Outputs a bool that indicates if router is enabled for this ap
//INT wifi_setApRouterEnable(INT apIndex, BOOL routerEnabled);          //P4 // sets the routerEnabled variable for this ap

INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg);       // creates configuration variables needed for WPA/WPS.  These variables are implementation dependent and in some implementations these variables are used by hostapd when it is started.  Specific variables that are needed are dependent on the hostapd implementation. These variables are set by WPA/WPS security functions in this wifi HAL.  If not needed for a particular implementation this function may simply return no error.
INT wifi_startHostApd();                                            // starts hostapd, uses the variables in the hostapd config with format compatible with the specific hostapd implementation
INT wifi_stopHostApd();                                             // stops hostapd

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.
//Device.WiFi.AccessPoint.{i}.Enable
INT wifi_setApEnable(INT apIndex, BOOL enable);                       // sets the AP enable status variable for the specified ap.
INT wifi_getApEnable(INT apIndex, BOOL *output_bool);                 // Outputs the setting of the internal variable that is set by wifi_setEnable().

//Device.WiFi.AccessPoint.{i}.Status
INT wifi_getApStatus(INT apIndex, CHAR *output_string);  				// Outputs the AP "Enabled" "Disabled" status from driver

//Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled
//Indicates whether or not beacons include the SSID name.
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output_bool);// outputs a 1 if SSID on the AP is enabled, else ouputs 0
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable);      // sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
//INT wifi_pushApSsidAdvertisementEnable(INT apIndex, BOOL enable);     // push the ssid advertisement enable variable to the hardware //Applying changs with wifi_applyRadioSettings()

//Device.WiFi.AccessPoint.{i}.RetryLimit
//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output);
INT wifi_setApRetryLimit(INT apIndex, UINT number);

//Device.WiFi.AccessPoint.{i}.WMMCapability
//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, UINT *output);

//Device.WiFi.AccessPoint.{i}.UAPSDCapability
//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, UINT *output);

//Device.WiFi.AccessPoint.{i}.WMMEnable
//Whether WMM support is currently enabled. When enabled, this is indicated in beacon frames.
INT wifi_getApWmmEnable(INT apIndex, BOOL *output);
INT wifi_setApWmmEnable(INT apIndex, BOOL enable);                    // enables/disables WMM on the hardwawre for this AP.  enable==1, disable == 0

//Device.WiFi.AccessPoint.{i}.UAPSDEnable
//Whether U-APSD support is currently enabled. When enabled, this is indicated in beacon frames. Note: U-APSD can only be enabled if WMM is also enabled.
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output);
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable);               // enables/disables Automatic Power Save Delivery on the hardwarwe for this AP

//Device.WiFi.AccessPoint.{i}.IsolationEnable
//Enables or disables device isolation.	A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output); //Tr181
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable); //Tr181

//Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices
//The maximum number of devices that can simultaneously be connected to the access point. A value of 0 means that there is no specific limit.
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output); //Tr181
INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number); //Tr181

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThreshold
//The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices. Setting this parameter does not actually limit the number of clients that can associate with this access point as that is controlled by MaxAssociatedDevices.	MaxAssociatedDevices or 50. The default value of this parameter should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50. A value of 0 means that there is no specific limit and Watermark calculation algorithm should be turned off.
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output); //Tr181	//P3
INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold); //Tr181		//P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkThresholdReached
//Number of times the current total number of associated device has reached the HighWatermarkThreshold value. This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well. Implementation specifics about this parameter are left to the product group and the device vendors. It can be updated whenever there is a new client association request to the access point.
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output); //Tr181 //P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermark
//Maximum number of associated devices that have ever associated with the access point concurrently since the last reset of the device or WiFi module.
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output); //Tr181	//P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_AssociatedDevicesHighWatermarkDate
//Date and Time at which the maximum number of associated devices ever associated with the access point concurrenlty since the last reset of the device or WiFi module (or in short when was X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This dateTime value is in UTC.
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds); //Tr181	//P3


//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingServiceCapability	boolean	R
//When true, indicates whether the access point supports interworking with external networks.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingServiceEnable	boolean	W
//Enables or disables capability of the access point to intework with external network. When enabled, the access point includes Interworking IE in the beacon frames.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_PasspointCapability	boolean	R
//Indicates whether this access point supports Passpoint (aka Hotspot 2.0). The Passpoint enabled AccessPoint must use WPA2-Enterprise security and WPS must not be enabled.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_PasspointEnable	boolean	W
//Whether Passpoint (aka Hotspot 2.0) support is currently enabled. When enabled, Passpoint specific information elemenets are indicated in beacon frames.

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_MAC_FilteringMode	string	R
//"The current operational state of the MAC Filtering Mode, Enumeration of:    Allow-ALL, Allow, Deny

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.Security.

//Device.WiFi.AccessPoint.{i}.Security.ModesSupported
//Comma-separated list of strings. Indicates which security modes this AccessPoint instance is capable of supporting. Each list item is an enumeration of: None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output);

//Device.WiFi.AccessPoint.{i}.Security.ModeEnabled	string	W
//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output);
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode);        // wifi_setApBasicEncryptionMode: sets an enviornment variable for the basic encryption mode.  Valid encMode strings are "None" or "WEPEncryption"

//Device.WiFi.AccessPoint.{i}.Security.WEPKey
//A WEP key expressed as a hexadecimal string.

//Device.WiFi.AccessPoint.{i}.Security.PreSharedKey
//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string);         // output_string must be pre-allocated as 64 character string by caller
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey);          // sets an enviornment variable for the psk. Input string preSharedKey must be a maximum of 64 characters

//Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase	string­(63)	W
//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string);        // outputs the passphrase, maximum 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase);           // sets the passphrase enviornment variable, max 63 characters

//Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval	unsignedInt	W
//The interval (expressed in seconds) in which the keys are re-generated.
//INT wifi_getApSecurityWpaRekeyInterval(INT apIndex, INT *output_int);         // outputs the rekey interval
//INT wifi_setApSecurityWpaRekeyInterval(INT apIndex, INT rekeyInterval);       // sets the internal variable for the rekey interval

//Device.WiFi.AccessPoint.{i}.Security.Reset
//When set to true, this AccessPoint instance's WiFi security settings are reset to their factory default values. The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
INT wifi_setApSecurityReset(INT apIndex);

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_KeyPassphrase	string­(63)	RW
//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.	If KeyPassphrase is written, then PreSharedKey is immediately generated. The ACS SHOULD NOT set both the KeyPassphrase and the PreSharedKey directly (the result of doing this is undefined). The key is generated as specified by WPA, which uses PBKDF2 from PKCS #5: Password-based Cryptography Specification Version 2.0 ([RFC2898]).	This custom parameter is defined to enable reading the Passphrase via TR-069 /ACS. When read it should return the actual passphrase
INT wifi_getApKeyPassphrase(INT apIndex, CHAR *output); //Tr181
INT wifi_setApKeyPassphrase(INT apIndex, CHAR *passphase); //Tr181

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_WEPKey	string	RW
//A WEP key expressed as a hexadecimal string.	WEPKey is used only if ModeEnabled is set to WEP-64 or WEP-128.	A 5 byte WEPKey corresponds to security mode WEP-64 and a 13 byte WEPKey corresponds to security mode WEP-128.	This custom parameter is defined to enable reading the WEPKey via TR-069/ACS. When read it should return the actual WEPKey.	If User enters 10 or 26 Hexadecimal characters, it should return keys as Hexadecimal characters.	If user enters 5 or 13 ASCII character key it should return key as ASCII characters.

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr
//Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort
//The IP Address and port number of the RADIUS server used for WLAN security. RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output); //Tr181
INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port); //Tr181

//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusServerRetries	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusServerRequestTimeout	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKLifetime	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKCaching	boolean	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.PMKCacheInterval	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.MaxAuthenticationAttempts	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.BlacklistTableTimeout	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.IdentityRequestRetryInterval	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.QuietPeriodAfterFailedAuthentication	int	W
//Device.WiFi.AccessPoint.{i}.Security.X_COMCAST-COM_RadiusSettings.RadiusSecret
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output); //Tr181
INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input); //Tr181


//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.WPS.
//Device.WiFi.AccessPoint.{i}.WPS.Enable
//Enables or disables WPS functionality for this access point.
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool);              // outputs the WPS enable state of this ap in output_bool
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue);               // sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsSupported
//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output); //Tr181

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled	string	W
//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output_string); // Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString); // sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods "USBFlashDrive","Ethernet","Label","Display","ExternalNFCToken","NFCInterface","PushButton","Keypad"

INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong);         // outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin);                   // set an enviornment variable for the WPS pin for the selected AP
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string); // Output string is either Not configured or Configured, max 32 characters
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin);                 // sets the WPS pin for this AP
INT wifi_setApWpsButtonPush(INT apIndex);                             // This function is called when the WPS push button has been pressed for this AP
INT wifi_cancelApWPS(INT apIndex);                                    // cancels WPS mode for this AP

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_OperatingStandard
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_OperatingChannelBandwidth
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_SNR
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_InterferenceSources	//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_DataFramesSentAck		//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_DataFramesSentNoAck	//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_BytesSent
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_BytesReceived
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_RSSI
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_MinRSSI				//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_MaxRSSI				//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_Disassociations		//P3
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.X_COMCAST-COM_AuthenticationFailures	//P3
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size); //Tr181

//------------------------------------------------------------------------------------------------------
////SSID stearing APIs using blacklisting
//INT wifi_setSsidSteeringPreferredList(INT radioIndex,INT apIndex, INT *preferredAPs[32]);  // prevent any client device from assocating with this ipIndex that has previously had a valid assocation on any of the listed "preferred" SSIDs unless SsidSteeringTimeout has expired for this device. The array lists all APs that are preferred over this AP.  Valid AP values are 1 to 32. Unused positions in this array must be set to 0. This setting becomes active when committed.  The wifi subsystem must default to no preferred SSID when initalized.
////Using the concept of an “preferred list” provides a solution to most use cases that requrie SSID Steering.  To implement this approach, the AP places the STA into the Access Control DENY list for a given SSID only if the STA has previously associated to one of the SSIDs in the “preferred list” that for SSID.
//INT wifi_setSsidSteeringTimout(INT radioIndex,INT apIndex, ULONG SsidSteeringTimout);  // only prevent the client device from assocatign with this apIndex if the device has connected to a preferred SSID within this timeout period - in units of hours.  This setting becomes active when committed.


//This call back will be invoked when new wifi client come to associate to AP.
typedef INT (*wifi_newApAssociatedDevice_callback)(INT apIndex, wifi_associated_dev_t *associated_dev);
//Callback registration function.
void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc);

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.AccessNetworkType
//Access Network Type value to be included in the Interworking IE in the beaconds. (refer 8.4.2.94 of IEEE Std 802.11-2012). Possible values are: 0 - Private network;1 - Private network with guest access;2 - Chargeable public network;3 - Free public network;4 - Personal device network;5 - Emergency services only network;6-13 - Reserved;14 - Test or experimental;15 - Wildcard
INT wifi_setAccessNetworkType(INT apIndex, INT accessNetworkType);   // P3

//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.Internet
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueGroupCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueTypeCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.HESSID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.DGAFEnable
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.ANQPDomainID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.VenueNamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.OperatorNamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.ConsortiumOIsNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.DomainNamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.3GPPNetworksNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_InterworkingService.NAIRealmsNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.VenueNames.{i}.VanueName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OperatorNames.{i}.OperatorName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.ConsortiumOIs.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.ConsortiumOIs.{i}.OI

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.DomainNames.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.DomainNames.{i}.DomainName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.MCC
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.3GPPNetworks.{i}.MNC

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.NAIRealmEncodingType
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.NAIRealm
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethodsNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.EAPMethod
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParametersNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.ID
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.NAIRealms.{i}.EAPMethods.{i}.AuthenticationParameters.{i}.Value

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.LinkStatus
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.AtCapacity
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.DownlinkSpeed
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.UplinkSpeed
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.DownlinkLoad
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.WANMetrics.UplinkLoad

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProvidersNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUServerURI
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUMethodsList
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.OSUNAI
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.NamesNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.IconsNumberOfEntries
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}ServiceDescriptionsNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Names.{i}.OSUProviderFriendlyName

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.IconWidth
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.IconHeight
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.Icons.{i}.LanguageCode

//-----------------------------------------------------------------------------------------------
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.LanguageCode
//Device.WiFi.AccessPoint.{i}.X_COMCAST-COM_Passpoint.OSU.OSUProviders.{i}.ServiceDescriptions.{i}.ServiceDescription

//-----------------------------------------------------------------------------------------------
//Device.IP.Diagnostics.
//Device.IP.Diagnostics.IPPing.
//Device.IP.Diagnostics.IPPing.DiagnosticsState
//Device.IP.Diagnostics.IPPing.Interface
//Device.IP.Diagnostics.IPPing.Host
//Device.IP.Diagnostics.IPPing.NumberOfRepetitions
//Device.IP.Diagnostics.IPPing.Timeout
//Device.IP.Diagnostics.IPPing.DataBlockSize
//Device.IP.Diagnostics.IPPing.DSCP

//Device.IP.Diagnostics.IPPing.SuccessCount
//Device.IP.Diagnostics.IPPing.FailureCount
//Device.IP.Diagnostics.IPPing.AverageResponseTime
//Device.IP.Diagnostics.IPPing.MinimumResponseTime
//Device.IP.Diagnostics.IPPing.MaximumResponseTime

//Start the ping test and get the result
//INT wifi_getIPDiagnosticsIPPingResult(wifi_diag_ipping_setting_t *input, wifi_diag_ipping_result_t *result); //Tr181
//--------------------------------------------------------------------------------------------------
// Wifi Airtime Management and QOS APIs to control contention based access to airtime
//INT wifi_clearDownLinkQos(INT apIndex);                             // clears the QOS parameters to the WMM default values for the downlink direction (from the access point to the stations.  This set must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_setDownLinkQos(INT apIndex, wifi_qos_t qosStruct);        // sets the QOS variables used in the downlink direction (from the access point to the stations).  Values must be allowable values per IEEE 802.11-2012 section 8.4.2.31.  Note:  Some implementations may requrie that all downlink APs on the same radio are set to the same QOS values. Default values are per the WMM spec.  This set must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_clearUpLinkQos(INT apIndex);                               // clears the QOS parameters to the WMM default values for the uplink direction (from the Wifi stations to the ap.  This must take affect when the api wifi_applySSIDSettings() is called.
//INT wifi_setUpLinkQos (INT apIndex, wifi_qos_t qosStruct);         // sets the QOS variables used in the uplink direction (from the Wifi stations to the AP). Values must be allowable values per IEEE 802.11-2012 section 8.4.2.31. The default values must be per the WMM spec.  This set must take affect when the api wifi_applySSIDSettings() is called.

//--------------------------------------------------------------------------------------------------
// Wifi Airtime Management and QOS APIs to control downlink queue prioritization
//INT wifi_getDownLinkQueuePrioritySupport (INT apIndex, INT *supportedPriorityLevels);  //This api is used to get the the number of supported downlink queuing priority levels for each AP/SSID.  If priority queuing levels for AP/SSIDs are not supported, the output should be set to 1. A value of 1 indicates that only the same priority level is supported for all AP/SSIDs.
//INT wifi_setDownLinkQueuePriority(INT apIndex, INT priorityLevel); // this sets the queue priority level for each AP/SSID in the downlink direction.  It is used with the downlink QOS api to manage priority access to airtime in the downlink direction.  This set must take affect when the api wifi_applySSIDSettings() is called.


#else
#error "! __WIFI_AP_HAL_H__"
#endif
