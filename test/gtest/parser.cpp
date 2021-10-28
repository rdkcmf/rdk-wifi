#include "gtest/gtest.h"
#include "../../include/wifi_common_hal.h"
#include "../../src/wifi_client_hal_priv.h"
#include <string>

using namespace std;

TEST(parser, parse)
{
    char* buffer = strdup("bssid / frequency / signal level / flags / ssid\n"
        "d4:5d:64:ec:3a:a8\t5500\t-29\t[WPA2-PSK+SAE-CCMP][WPS][ESS]\tASUSRAP_ 5823364335\n"
        "78:3e:53:f4:6c:53\t5180\t-36\t[WPA2-PSK-CCMP][WPS-AUTH][ESS]\tSKYFEF31\n"
        "86:da:88:7b:2c:2b\t5180\t-39\t[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]\tG LASS\n"
        "d4:5d:64:ec:3a:a4\t5300\t-43\t[WPA-PSK-CCMP][WPA2-PSK-CCMP][WPS][ESS]\tQ LOUNGEONE\n"
        "38:a6:ce:85:f9:4d\t5180\t-44\t[WPA2-PSK-CCMP][WPS][ESS]\tSKYFCDE3\n"
        "44:fe:3b:12:c5:e3\t5180\t-47\t[WPA2-PSK-CCMP][WPS][ESS]\tBTHHUB7_ 4993725425\n"
        "7e:da:88:7b:42:0f\t5180\t-48\t[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]\tG LASS\n"
        "74:da:88:7b:42:0f\t5180\t-48\t[WPA2-PSK-CCMP][ESS]\t\n"
        "82:da:88:7b:3c:f3\t5180\t-50\t[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]\tG LASS\n"
        "90:02:18:60:ba:0a\t5180\t-49\t[WPA2-PSK-CCMP][WPS][ESS]\t SKYF88D6\n"
        "74:da:88:7b:3c:f3\t5180\t-49\t[WPA2-PSK-CCMP][ESS]\t\n"
        "78:3e:53:87:ee:8b\t5180\t-52\t[WPA2-PSK-CCMP][WPS][ESS]\tSKYB6F14\n"
        "24:a7:dc:ff:7f:85\t5180\t-54\t[WPA2-PSK-CCMP][WPS][ESS]\tRTCABIN\n"
        "20:47:ed:b1:9d:33\t5180\t-54\t[WPA2-PSK-CCMP][WPS][ESS]\tSKY97888\n"
        "04:81:9b:24:1a:2d\t5180\t-57\t[WPA2-PSK-CCMP][WPS][ESS]\tSKYQ4XLB\n"
        "78:3e:53:9b:40:0b\t5180\t-59\t[WPA2-PSK-CCMP][WPS-AUTH][ESS]\tSKYSE210\n"
        "78:3e:53:f4:72:0b\t5180\t-69\t[WPA2-PSK-CCMP][WPS-AUTH][ESS]\tSKYSE210\n"
        "74:da:88:7b:42:0e\t2462\t-35\t[WPA2-PSK-CCMP][ESS]\t\n"
        "86:da:88:7b:2c:2a\t2462\t-38\t[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]\tG LASS\n"
        "7e:da:88:7b:42:0e\t2462\t-44\t[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]\tG LASS\n"
        "82:da:88:7b:3c:f2\t2462\t-47\t[WPA2-PSK+FT/PSK-CCMP][WPS][ESS]\tG LASS\n"
        "74:da:88:7b:3c:f2\t2462\t-48\t[WPA2-PSK-CCMP][ESS]\t\n"
        "1a:74:2e:67:57:42\t5180\t-65\t[WPA2-PSK-CCMP][WPS][ESS][P2P]\t\\x00\\x00 \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\n"
        "d4:5d:64:ec:3a:a0\t2412\t-39\t[WPA2-PSK+SAE-CCMP][WPS][ESS]\tQLOUNGEO NE\n"
        "64:a0:e7:5e:cb:5e\t5220\t-89\t[WPA2-EAP+FT/EAP-CCMP][ESS]\tSkyStaff WIFI\n"
        "44:fe:3b:12:c5:e4\t2462\t-36\t[WPA2-PSK-CCMP][WPS][ESS]\tBTHHUB7_ 4993725425\n"
        "62:fe:3b:12:c5:e0\t2462\t-37\t[WPA2-PSK-CCMP][ESS]\t\\x00\\x00\\x00\\x00 \\x00\\x00\\x00\\x00\\x00\n"
        "04:81:9b:24:1a:2a\t2412\t-47\t[WPA2-PSK-CCMP][WPS][ESS]\tSKYQ4XLB\n"
        "70:50:af:00:05:5a\t2447\t-48\t[WPA2-PSK-CCMP][WPS][ESS]\tSH3_CHEA D_4844344753\n"
        "24:a7:dc:ff:7f:82\t2412\t-56\t[WPA2-PSK-CCMP][WPS][ESS]\tRTCABIN\n"
        "90:4d:4a:07:aa:5e\t2437\t-73\t[WPA2-PSK-CCMP][WPS][ESS]\tBTHUB6_4 322354256\n"
        "64:a0:e7:5e:c4:71\t2412\t-75\t[WPA2-EAP+FT/EAP-CCMP][ESS]\tSkyStaff WIFI\n"
        "78:3e:53:d7:36:fe\t2412\t-75\t[WPA2-PSK-CCMP][WPS][ESS]\tSupport2\n"
        "a8:b1:d4:6d:57:7f\t5200\t-94\t[WPA2-EAP+FT/EAP-CCMP][ESS]\tSkyCorpo rateWIFI\n"
        "64:a0:e7:5e:cb:5f\t5220\t-94\t[WPA2-EAP+FT/EAP-CCMP][ESS]\tSkyCorpo rateWIFI\n"
        "58:b6:33:2a:71:cc\t5180\t-48\t[ESS]\t\n"
        "64:a0:e7:5e:cb:5d\t5220\t-88\t[ESS]\tSkyVisitorWIFI\n"
        "58:b6:33:2a:71:c8\t2417\t-38\t[ESS]\t\n"
        "64:a0:e7:5e:c4:72\t2412\t-73\t[ESS]\tSkyVisitorWIFI\n"
        "64:a0:e7:5e:cb:52\t2437\t-75\t[ESS]\tSkyVisitorWIFI\n");

    printf("before parse_scan_results\n");
    buffer[0]='u';
    INT ap_count = parse_scan_results(buffer, strlen(buffer));
    printf("after parse_scan_results count=%d\n", ap_count);
    free(buffer);
    EXPECT_EQ(ap_count, 32);
}