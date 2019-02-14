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

    module: wifi_common_hal.h

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and
        structure definitions used for the RDK-Broadband
        Wifi radio hardware abstraction layer

        NOTE:
        THIS VERSION IS AN EARLY DRAFT INTENDED TO GET COMMENTS FROM COMCAST.
        TESTING HAS NOT YET BEEN COMPLETED.

    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support Wifi drivers
        through an open API.

    ---------------------------------------------------------------

    HAL version:

        The version of the Wifi HAL is specified in #defines below.

    ---------------------------------------------------------------

    author:

        zhicheng_qiu@cable.comcast.com
        Charles Moreman, moremac@cisco.com


**********************************************************************/

#ifndef __WIFI_COMMON_HAL_H__
#define __WIFI_COMMON_HAL_H__


#ifndef ULONG
#define ULONG unsigned long
#endif

#ifndef BOOL
#define BOOL  unsigned char
#endif

#ifndef CHAR
#define CHAR  char
#endif

#ifndef UCHAR
#define UCHAR unsigned char
#endif

#ifndef INT
#define INT   int
#endif

#ifndef UINT
#define UINT  unsigned int
#endif

#ifndef FLOAT
#define FLOAT  float
#endif

#ifndef TRUE
#define TRUE     1
#endif

#ifndef FALSE
#define FALSE    0
#endif

#ifndef ENABLE
#define ENABLE   1
#endif

#ifndef RETURN_OK
#define RETURN_OK   0
#endif

#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif


#ifndef RADIO_INDEX_1
#define RADIO_INDEX_1 1
#define RADIO_INDEX_2 2
#define AP_INDEX_1 1
#define AP_INDEX_2 2
#define AP_INDEX_3 3
#define AP_INDEX_4 4
#define AP_INDEX_5 5
#define AP_INDEX_6 6
#define AP_INDEX_7 7
#define AP_INDEX_8 8
#define AP_INDEX_9 9
#define AP_INDEX_10 10
#define AP_INDEX_11 11
#define AP_INDEX_12 12
#define AP_INDEX_13 13
#define AP_INDEX_14 14
#define AP_INDEX_15 15
#define AP_INDEX_16 16
#endif

//defines for HAL version 2.0.0
#define WIFI_HAL_MAJOR_VERSION 2   // This is the major verion of this HAL.
#define WIFI_HAL_MINOR_VERSION 0   // This is the minor verson of the HAL.
#define WIFI_HAL_MAINTENANCE_VERSION 0   // This is the maintenance version of the HAL.



/* Wifi RSSI Levels */
typedef enum {
    WIFI_RSSI_NONE = 0,      //!< No signal (0 bar)
    WIFI_RSSI_POOR,          //!< Poor (1 bar)
    WIFI_RSSI_FAIR,          //!< Fair (2 bars)
    WIFI_RSSI_GOOD,          //!< Good (3 bars)
    WIFI_RSSI_EXCELLENT,     //!< Excellent (4 bars)
    WIFI_RSSI_MAX
} wifiRSSILevel_t;

/*wifi wpa supplicant status codes*/
typedef enum _WiFiHalStatus_t {
    WIFISTATUS_HAL_DISCONNECTED,
    WIFISTATUS_HAL_INTERFACE_DISABLED,
    WIFISTATUS_HAL_INACTIVE,
    WIFISTATUS_HAL_SCANNING,
    WIFISTATUS_HAL_AUTHENTICATING,
    WIFISTATUS_HAL_ASSOCIATING,
    WIFISTATUS_HAL_ASSOCIATED,
    WIFISTATUS_HAL_4WAY_HANDSHAKE,
    WIFISTATUS_HAL_GROUP_HANDSHAKE,
    WIFISTATUS_HAL_COMPLETED
} WiFiHalStatus_t;

/* Wifi Connection codes */
typedef enum {
    WIFI_HAL_SUCCESS = 0,                    /**< Successful connect/disconnect */
    WIFI_HAL_CONNECTING,                     /**< Attempting to connect to a Network/AP using wps or SSID selection*/
    WIFI_HAL_DISCONNECTING = 10,             /**< Attempting to disconnect to a Network/AP */

    /* Failure/Error Codes*/
    WIFI_HAL_ERROR_NOT_FOUND = 20,           /**< Device/AP not found*/
    WIFI_HAL_ERROR_TIMEOUT_EXPIRED,          /**< Timeout expired */
    WIFI_HAL_ERROR_DEV_DISCONNECT,           /**< Failed/Error in Device/AP Disconnect */
    WIFI_HAL_ERROR_SSID_CHANGED,             /**< the SSID of the network changed */
    WIFI_HAL_ERROR_CONNECTION_LOST,          /**< the connection to the network was lost */
    WIFI_HAL_ERROR_CONNECTION_FAILED,        /**< the connection failed for an unknown reason */
    WIFI_HAL_ERROR_CONNECTION_INTERRUPTED,   /**< the connection was interrupted */
    WIFI_HAL_ERROR_INVALID_CREDENTIALS,      /**< the connection failed due to invalid credentials */
    WIFI_HAL_UNRECOVERABLE_ERROR,            /**< The device has encountered an unrecoverable (driver or hardware failures) errors */
    WIFI_HAL_ERROR_AUTH_FAILED,              /**< the connection failed due to authentication failure */
    WIFI_HAL_ERROR_UNKNOWN = 40,             /**< Unknown/unspecified error */
} wifiStatusCode_t;

typedef enum
{
    WIFI_SECURITY_NONE = 0,
    WIFI_SECURITY_WEP_64,
    WIFI_SECURITY_WEP_128,
    WIFI_SECURITY_WPA_PSK_TKIP,
    WIFI_SECURITY_WPA_PSK_AES,
    WIFI_SECURITY_WPA2_PSK_TKIP,
    WIFI_SECURITY_WPA2_PSK_AES,
    WIFI_SECURITY_WPA_ENTERPRISE_TKIP,
    WIFI_SECURITY_WPA_ENTERPRISE_AES,
    WIFI_SECURITY_WPA2_ENTERPRISE_TKIP,
    WIFI_SECURITY_WPA2_ENTERPRISE_AES,
    WIFI_SECURITY_WPA_WPA2_PSK,                     //!< WPA2(Pre-Shared Key) with TKIP AES encryption
    WIFI_SECURITY_WPA_WPA2_ENTERPRISE,              //!< WPA,WPA2 Enterprise with TKIP AES encryption
    WIFI_SECURITY_NOT_SUPPORTED = 15,
} wifiSecurityMode_t;

/**********************************************************************
                STRUCTURE DEFINITIONS
**********************************************************************/

typedef struct _wifi_radioTrafficStats
{
    ULONG radio_BytesSent;	//The total number of bytes transmitted out of the interface, including framing characters.
    ULONG radio_BytesReceived;	//The total number of bytes received on the interface, including framing characters.
    ULONG radio_PacketsSent;	//The total number of packets transmitted out of the interface.
    ULONG radio_PacketsReceived; //The total number of packets received on the interface.

    ULONG radio_ErrorsSent;	//The total number of outbound packets that could not be transmitted because of errors.
    ULONG radio_ErrorsReceived;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    ULONG radio_DiscardPacketsSent; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
    ULONG radio_DiscardPacketsReceived; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
    ULONG radio_PLCPErrorCount;	//The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.
    ULONG radio_FCSErrorCount;	//The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
    ULONG radio_InvalidMACCount;	//The number of packets that were received with a detected invalid MAC header error.
    ULONG radio_PacketsOtherReceived;	//The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
    INT   radio_NoiseFloor; 	//The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
    ULONG radio_ChannelUtilization; //Percentage of time the channel was occupied by the radio’s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
    INT   radio_ActivityFactor; //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    INT   radio_CarrierSenseThreshold_Exceeded; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    INT   radio_RetransmissionMetirc; //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage
    INT   radio_MaximumNoiseFloorOnChannel; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
    INT   radio_MinimumNoiseFloorOnChannel; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    INT   radio_MedianNoiseFloorOnChannel; //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    ULONG radio_StatisticsStartTime; 	 //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

} wifi_radioTrafficStats_t;	//for radio only

typedef struct _wifi_radioTrafficStatsMeasure
{
    INT   radio_RadioStatisticsMeasuringRate; //Input //"The rate at which radio related statistics are periodically collected.  Only statistics that explicitly indicate the use of this parameter MUST use the rate set in this parameter  Other parameter's are assumed to collect data in real-time or nearly real-time. Default value is 30 seconds.  This parameter MUST be persistent across reboots. If this parameter is changed,  then use of the new rate MUST be deferred until the start of the next interval and all metrics using this rate MUST return -1 until the completion of the next full interval Units in Seconds"
    INT   radio_RadioStatisticsMeasuringInterval; //Input //The interval for which radio data MUST be retained in order and at the end of which appropriate calculations are executed and reflected in the associated radio object's.  Only statistics that explicitly indicate the use of this parameter MUST use the interval set in this parameter  Default value is 30 minutes.  This parameter MUST be persistent across reboots.   If this item is modified, then all metrics leveraging this interval as well as the metrics “Total number 802.11 packet of TX” and “Total number 802.11 packet of RX“ MUST be re-initialized immediately.  Additionally, the “Statistics Start Time” must be reset to the current time. Units in Seconds
} wifi_radioTrafficStatsMeasure_t;	//for radio only


typedef struct _wifi_ssidTrafficStats
{
    ULONG ssid_BytesSent;	//The total number of bytes transmitted out of the interface, including framing characters.
    ULONG ssid_BytesReceived;	//The total number of bytes received on the interface, including framing characters.
    ULONG ssid_PacketsSent;	//The total number of packets transmitted out of the interface.
    ULONG ssid_PacketsReceived; //The total number of packets received on the interface.

    ULONG ssid_RetransCount;	//The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two.
    ULONG ssid_FailedRetransCount; //The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. This parameter is based on dot11FailedCount from [802.11-2012].
    ULONG ssid_RetryCount;  //The number of packets that were successfully transmitted after one or more retransmissions. This parameter is based on dot11RetryCount from [802.11-2012].
    ULONG ssid_MultipleRetryCount; //The number of packets that were successfully transmitted after more than one retransmission. This parameter is based on dot11MultipleRetryCount from [802.11-2012].
    ULONG ssid_ACKFailureCount;  //The number of expected ACKs that were never received. This parameter is based on dot11ACKFailureCount from [802.11-2012].
    ULONG ssid_AggregatedPacketCount; //The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac.

    ULONG ssid_ErrorsSent;	//The total number of outbound packets that could not be transmitted because of errors.
    ULONG ssid_ErrorsReceived;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    ULONG ssid_UnicastPacketsSent;	//The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    ULONG ssid_UnicastPacketsReceived;  //The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer.
    ULONG ssid_DiscardedPacketsSent; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
    ULONG ssid_DiscardedPacketsReceived; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
    ULONG ssid_MulticastPacketsSent; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent.
    ULONG ssid_MulticastPacketsReceived; //The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer.
    ULONG ssid_BroadcastPacketsSent;  //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
    ULONG ssid_BroadcastPacketsRecevied; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
    ULONG ssid_UnknownPacketsReceived;  //The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol.

} wifi_ssidTrafficStats_t;  //for ssid only


//Please do not edit the elements for this data structure
typedef struct _wifi_neighbor_ap
{
    //CHAR  ap_Radio[64];	//The value MUST be the path name of a row in the Device.WiFi.Radio table. The Radio that detected the neighboring WiFi SSID.
    CHAR  ap_SSID[64];	//The current service set identifier in use by the neighboring WiFi SSID. The value MAY be empty for hidden SSIDs.
    CHAR  ap_BSSID[64];	//[MACAddress] The BSSID used for the neighboring WiFi SSID.
    CHAR  ap_Mode[64];	//The mode the neighboring WiFi radio is operating in. Enumeration of: AdHoc, Infrastructure
    UINT  ap_Channel;	//The current radio channel used by the neighboring WiFi radio.
    INT   ap_SignalStrength;	//An indicator of radio signal strength (RSSI) of the neighboring WiFi radio measured in dBm, as an average of the last 100 packets received.
    CHAR  ap_SecurityModeEnabled[64];	//The type of encryption the neighboring WiFi SSID advertises. Enumeration of:None, WPA-WPA2 etc.
    CHAR  ap_EncryptionMode[64];	//Comma-separated list of strings. The type of encryption the neighboring WiFi SSID advertises. Each list item is an enumeration of: TKIP, AES
    CHAR  ap_OperatingFrequencyBand[16];	//Indicates the frequency band at which the radio this SSID instance is operating. Enumeration of:2.4GHz, 5GHz
    CHAR  ap_SupportedStandards[64];	//Comma-separated list of strings. List items indicate which IEEE 802.11 standards this Result instance can support simultaneously, in the frequency band specified by OperatingFrequencyBand. Each list item is an enumeration of:
    CHAR  ap_OperatingStandards[16];	//Comma-separated list of strings. Each list item MUST be a member of the list reported by theSupportedStandards parameter. List items indicate which IEEE 802.11 standard that is detected for thisResult.
    CHAR  ap_OperatingChannelBandwidth[16];	//Indicates the bandwidth at which the channel is operating. Enumeration of:
    UINT  ap_BeaconPeriod;	//Time interval (in ms) between transmitting beacons.
    INT   ap_Noise;	//Indicator of average noise strength (in dBm) received from the neighboring WiFi radio.
    CHAR  ap_BasicDataTransferRates[256];	//Comma-separated list (maximum list length 256) of strings. Basic data transmit rates (in Mbps) for the SSID. For example, if BasicDataTransferRates is "1,2", this indicates that the SSID is operating with basic rates of 1 Mbps and 2 Mbps.
    CHAR  ap_SupportedDataTransferRates[256];	//Comma-separated list (maximum list length 256) of strings. Data transmit rates (in Mbps) for unicast frames at which the SSID will permit a station to connect. For example, if SupportedDataTransferRates is "1,2,5.5", this indicates that the SSID will only permit connections at 1 Mbps, 2 Mbps and 5.5 Mbps.
    UINT  ap_DTIMPeriod;	//The number of beacon intervals that elapse between transmission of Beacon frames containing a TIM element whose DTIM count field is 0. This value is transmitted in the DTIM Period field of beacon frames. [802.11-2012]
    UINT  ap_ChannelUtilization[64];	//Indicates the fraction of the time AP senses that the channel is in use by the neighboring AP for transmissions.

} wifi_neighbor_ap_t;	//COSA_DML_NEIGHTBOURING_WIFI_RESULT

typedef struct _wifi_diag_ipping_setting
{
    CHAR  ipping_Interface[256];	//The value MUST be the path name of a row in the IP.Interface table. The IP-layer interface over which the test is to be performed. This identifies the source IP address to use when performing the test. Example: Device.IP.Interface.1. If an empty string is specified, the CPE MUST use the interface as directed by its routing policy (Forwarding table entries) to determine the appropriate interface.
    CHAR  ipping_Host[256];	//Host name or address of the host to ping. In the case where Host is specified by name, and the name resolves to more than one address, it is up to the device implementation to choose which address to use.
    UINT  ipping_NumberOfRepetitions;	//Number of repetitions of the ping test to perform before reporting the results.
    UINT  ipping_Timeout;	//Timeout in milliseconds for the ping test.
    UINT  ipping_DataBlockSize;	//Size of the data block in bytes to be sent for each ping.
    UINT  ipping_DSCP;	//DiffServ codepoint to be used for the test packets. By default the CPE SHOULD set this value to zero.

} wifi_diag_ipping_setting_t;

typedef struct _wifi_diag_ipping_result
{
    CHAR  ipping_DiagnosticsState[64];	//Indicates availability of diagnostic data. Enumeration of:	Complete, Error_CannotResolveHostName, 	Error_Internal, Error_Other
    UINT  ipping_SuccessCount;	//Result parameter indicating the number of successful pings (those in which a successful response was received prior to the timeout) in the most recent ping test.
    UINT  ipping_FailureCount;	//Result parameter indicating the number of failed pings in the most recent ping test.
    UINT  ipping_AverageResponseTime;	//Result parameter indicating the average response time in milliseconds over all repetitions with successful responses of the most recent ping test. If there were no successful responses, this value MUST be zero.
    UINT  ipping_MinimumResponseTime;	//Result parameter indicating the minimum response time in milliseconds over all repetitions with successful responses of the most recent ping test. If there were no successful responses, this value MUST be zero.
    UINT  ipping_MaximumResponseTime;	//Result parameter indicating the maximum response time in milliseconds over all repetitions with successful responses of the most recent ping test. If there were no successful responses, this value MUST be zero.

} wifi_diag_ipping_result_t;


typedef struct _wifi_sta_stats
{
    CHAR  sta_SSID[64];         // The current connected SSID name.
    CHAR  sta_BSSID[64];        // The BSSID used for connected SSID.
    CHAR  sta_BAND[16];        //!< The BAND used for connected SSID.
    FLOAT sta_PhyRate;          // Indicates the Physical rate (Mbps)
    FLOAT sta_Noise;            // Indicator of average noise strength (in dBm) received from the connected WiFi radio.
    FLOAT sta_RSSI;             // RSSI value in dBm
    UINT  sta_LastDataDownlinkRate;		/* The data transmit rate in kbps that was most recently used for transmission from the access point to the end point device. */
    UINT  sta_LastDataUplinkRate;		/* The data transmit rate in kbps that was most recently used for transmission from the end point to the access point device.*/
    UINT  sta_Retransmissions;			/* The number of packets that had to be re-transmitted, from the last 100 packets sent to the access point. \
											Multiple re-transmissions of the same packet count as one.*/
} wifi_sta_stats_t;


//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string);   //RDKB

//---------------------------------------------------------------------------------------------------
//
// Wifi subsystem level APIs that are common to Client and Access Point devices.
//
//---------------------------------------------------------------------------------------------------

//clears internal variables to implement a factory reset of the Wi-Fi subsystem
INT wifi_factoryReset();	//RDKB

//Restore all radio parameters without touch access point parameters
INT wifi_factoryResetRadios(); //RDKB

//Restore selected radio parameters without touch access point parameters
INT wifi_factoryResetRadio(int radioIndex); 	//RDKB

//Set the system LED status
//INT wifi_setLED(INT apIndex, BOOL enable);	//RDKB

// Initializes the wifi subsystem (all radios)
INT wifi_init();                              //RDKB

// resets the wifi subsystem, deletes all APs
INT wifi_reset();                            //RDKB

// turns off transmit power for the entire Wifi subsystem, for all radios
INT wifi_down();                       		//RDKB

// uninitilizes wifi 
INT wifi_uninit();
                       		//RDKB
// creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_createInitialConfigFiles();

// log wifi parameters  format SSID:   BSSID:  ulChan: Noise:  RSSI:
void wifi_getStats(INT radioIndex, wifi_sta_stats_t *wifi_sta_stats);


//---------------------------------------------------------------------------------------------------
//Wifi Tr181 API

//Device.WiFi.

//Device.WiFi.RadioNumberOfEntries
//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output); //Tr181

//Device.WiFi.SSIDNumberOfEntries
//Get the total number of SSID entries in this wifi subsystem
INT wifi_getSSIDNumberOfEntries(ULONG *output); //Tr181

//Device.WiFi.AccessPointNumberOfEntries

//Device.WiFi.EndPointNumberOfEntries
//End points are managed by RDKB
//INT wifi_getEndPointNumberOfEntries(INT radioIndex, ULONG *output); //Tr181

//---------------------------------------------------------------------------------------------------
//
// Wifi radio level APIs that are common to Client and Access Point devices
//
//---------------------------------------------------------------------------------------------------

//Device.WiFi.Radio.
//Device.WiFi.Radio.{i}.Enable
//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool);	//RDKB

//Set the Radio enable config parameter
INT wifi_setRadioEnable(INT radioIndex, BOOL enable);		//RDKB

//Device.WiFi.Radio.{i}.Status
//Get the Radio enable status. In the success case it should populate the output_string with "UP". Else it will be "DOWN"
INT wifi_getRadioStatus(INT radioIndex, CHAR *output_string);	//RDKB

//Device.WiFi.Radio.{i}.Alias

//Device.WiFi.Radio.{i}.Name
//Get the Radio Interface name from platform, eg "wifi0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string); //Tr181

//Device.WiFi.Radio.{i}.LastChange

//Device.WiFi.Radio.{i}.LowerLayers

//Device.WiFi.Radio.{i}.Upstream

//Device.WiFi.Radio.{i}.MaxBitRate
//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string);	//RDKB

//Device.WiFi.Radio.{i}.SupportedFrequencyBands
//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string);	//RDKB

//Device.WiFi.Radio.{i}.OperatingFrequencyBand
//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string); //Tr181

//Device.WiFi.Radio.{i}.SupportedStandards
//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string); //Tr181

//Device.WiFi.Radio.{i}.OperatingStandards
//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly);	//RDKB
//Set the radio operating mode, and pure mode flag.
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag);	//RDKB

//Device.WiFi.Radio.{i}.PossibleChannels
//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string);	//RDKB

//Device.WiFi.Radio.{i}.ChannelsInUse
//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string);	//RDKB

//Device.WiFi.Radio.{i}.Channel
//Get the running channel number
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong);	//RDKB
//Set the running channel number
INT wifi_setRadioChannel(INT radioIndex, ULONG channel);	//RDKB	//AP only

//Device.WiFi.Radio.{i}.AutoChannelSupported
//Check if the driver support the ACS
INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool); //Tr181
//Get the ACS enable status
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool);	//RDKB
//Set the ACS enable status
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable);	//RDKB

//Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod
//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong); //Tr181
//Set the ACS refresh period in seconds
INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds); //Tr181

//Device.WiFi.Radio.{i}.OperatingChannelBandwidth
//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string); //Tr181
//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth); //Tr181	//AP only

//Device.WiFi.Radio.{i}.ExtensionChannel
//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string); //Tr181
//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string); //Tr181	//AP only

//Device.WiFi.Radio.{i}.GuardInterval
//Get the guard interval value. eg "400nsec" or "800nsec"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string);	//Tr181
//Set the guard interval value.
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string);	//Tr181

//Device.WiFi.Radio.{i}.MCS
//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_INT); //Tr181
//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS); //Tr181

//Device.WiFi.Radio.{i}.TransmitPowerSupported
//Get supported Transmit Power list, eg : "0,25,50,75,100"
//The output_list is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list); //Tr181

//Device.WiFi.Radio.{i}.TransmitPower
//Get current Transmit Power, eg "75", "100"
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, INT *output_INT);	//RDKB
//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower);	//RDKB

//Device.WiFi.Radio.{i}.IEEE80211hSupported
//get 80211h Supported.  80211h solves interference with satellites and radar using the same 5 GHz frequency band
int wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported);  //Tr181
//Device.WiFi.Radio.{i}.IEEE80211hEnabled
//Get 80211h feature enable
int wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable);  //Tr181
//Set 80211h feature enable
int wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable);  //Tr181

//Device.WiFi.Radio.{i}.RegulatoryDomain
INT wifi_getRegulatoryDomain(INT radioIndex, CHAR* output_string);

//Device.WiFi.Radio.{i}.X_COMCAST-COM_CarrierSenseThresholdRange
//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output);  //P3

//Device.WiFi.Radio.{i}.X_COMCAST-COM_CarrierSenseThresholdInUse
//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output);	//P3
INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold);	//P3

//Device.WiFi.Radio.{i}.X_COMCAST-COM_ChannelSwitchingCount
//This parameter indicates the total number of Channel Changes.  Reset the parameter every 24 hrs or reboot
INT wifi_getRadioChannelSwitchingCount(INT radioIndex, INT *output); 	//P3

//Device.WiFi.Radio.{i}.BeaconPeriod
//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output);
INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod);

//Device.WiFi.Radio.{i}.BasicDataTransmitRates
//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output);
INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates);

//---------------------------------------------------------------------------------------------------
//Device.WiFi.Radio.{i}.Stats.

//Device.WiFi.Radio.{i}.Stats.BytesSent
//Device.WiFi.Radio.{i}.Stats.BytesReceived
//Device.WiFi.Radio.{i}.Stats.PacketsSent
//Device.WiFi.Radio.{i}.Stats.PacketsReceived
//Device.WiFi.Radio.{i}.Stats.ErrorsSent
//Device.WiFi.Radio.{i}.Stats.ErrorsReceived
//Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent
//Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived
//Device.WiFi.Radio.{i}.Stats.PLCPErrorCount
//Device.WiFi.Radio.{i}.Stats.FCSErrorCount
//Device.WiFi.Radio.{i}.Stats.InvalidMACCount
//Device.WiFi.Radio.{i}.Stats.PacketsOtherReceived
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_NoiseFloor
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ChannelUtilization
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ActivityFactor
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_CarrierSenseThreshold_Exceeded
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RetransmissionMetirc
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_MaximumNoiseFloorOnChannel
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_MinimumNoiseFloorOnChannel
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_MedianNoiseFloorOnChannel
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_StatisticsStartTime
//Get detail radio traffic static info
INT wifi_getRadioTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct); //Tr181

//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RadioStatisticsMeasuringRate
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_RadioStatisticsMeasuringInterval
//Set radio traffic static Measureing rules
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct); //Tr181


//-----------------------------------------------------------------------------------------------
//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ReceivedSignalLevel.{i}.

//Device.WiFi.Radio.{i}.Stats.X_COMCAST-COM_ReceivedSignalLevel.{i}.ReceivedSignalLevel
//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the clients current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected clients current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histograms bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel); //Tr181

//-----------------------------------------------------------------------------------------------------
//This API is used to apply (push) all previously set radio level variables and make these settings active in the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex);

//---------------------------------------------------------------------------------------------------
//
// Wifi SSID level APIs common to Client and Access Point devices.
//
//---------------------------------------------------------------------------------------------------

//Device.WiFi.SSID.{i}.

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex);

//Device.WiFi.SSID.{i}.Enable
//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool); //Tr181
//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable); //Tr181

//Device.WiFi.SSID.{i}.Status
//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string); //Tr181

//Device.WiFi.SSID.{i}.Alias

//Device.WiFi.SSID.{i}.Name
INT wifi_getSSIDName(INT apIndex, CHAR *output_string);                 // Outputs a 32 byte or less string indicating the SSID name.  Sring buffer must be preallocated by the caller.
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string);                   // accepts a max 32 byte string and sets an internal variable to the SSID name
//INT wifi_pushSSIDName(INT apIndex, CHAR *ssid);                         // push the ssid name to the hardware //repleaced by wifi_applySSIDSettings

//Device.WiFi.SSID.{i}.LastChange

//Device.WiFi.SSID.{i}.LowerLayers

//Device.WiFi.SSID.{i}.BSSID
//Get the BSSID
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string);	//RDKB

//Device.WiFi.SSID.{i}.MACAddress
//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string); //Tr181

//Device.WiFi.SSID.{i}.SSID

//-----------------------------------------------------------------------------------------------
//Device.WiFi.SSID.{i}.Stats.
//Device.WiFi.SSID.{i}.Stats.BytesSent
//Device.WiFi.SSID.{i}.Stats.BytesReceived
//Device.WiFi.SSID.{i}.Stats.PacketsSent
//Device.WiFi.SSID.{i}.Stats.PacketsReceived

//Device.WiFi.SSID.{i}.Stats.RetransCount
//Device.WiFi.SSID.{i}.Stats.FailedRetransCount
//Device.WiFi.SSID.{i}.Stats.RetryCount
//Device.WiFi.SSID.{i}.Stats.MultipleRetryCount
//Device.WiFi.SSID.{i}.Stats.ACKFailureCount
//Device.WiFi.SSID.{i}.Stats.AggregatedPacketCount

//Device.WiFi.SSID.{i}.Stats.ErrorsSent
//Device.WiFi.SSID.{i}.Stats.ErrorsReceived
//Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent
//Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived
//Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent
//Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived
//Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent
//Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived
//Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent
//Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived
//Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived

//Get the basic SSID traffic static info
INT wifi_getSSIDTrafficStats(INT ssidIndex, wifi_ssidTrafficStats_t *output_struct); //Tr181

//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex);


//-----------------------------------------------------------------------------------------------
//Device.WiFi.NeighboringWiFiDiagnostic.
//Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState
//Device.WiFi.NeighboringWiFiDiagnostic.ResultNumberOfEntries

//-----------------------------------------------------------------------------------------------
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Radio
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SSID
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BSSID
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Mode
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Channel
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SignalStrength
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SecurityModeEnabled
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.EncryptionMode
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingFrequencyBand
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SupportedStandards
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingStandards
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingChannelBandwidth
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BeaconPeriod
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Noise
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BasicDataTransferRates
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SupportedDataTransferRates
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.DTIMPeriod
//Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.X_COMCAST-COM_ChannelUtilization

//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult(INT radioIndex, wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size); //Tr181

#endif
