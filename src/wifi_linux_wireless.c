/*
* If not stated otherwise in this file or this component's Licenses.txt file the
* following copyright and licenses apply:
*
* Copyright 2022 RDK Management
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
//#include <linux/wireless.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <linux/wireless.h>

#include <wifi_common_hal.h>
#include "wifi_log.h"

bool wifi_interfaceIsWireless(const char * ifname)
{
  bool hasWirelessExtensions = false;

  int soc = socket(AF_INET, SOCK_STREAM, 0);
  if (soc == -1) {
    WIFI_LOG_WARN("error creating socket while looking for wireless extensions. %d\n",
      errno);
    return false;
  }
  else {
    struct iwreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(soc, SIOCGIWNAME, &req) != -1)
      hasWirelessExtensions = true;

    close(soc);
  }

  return hasWirelessExtensions;
}
