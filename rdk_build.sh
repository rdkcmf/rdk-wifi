#!/bin/bash
####################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
#  Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################
#

# use -e to fail on any shell issue
# -e is the requirement from Build Framework
set -e

RDK_PATCHES=$RDK_PROJECT_ROOT_PATH/build/components/opensource/patch

# default PATHs - use `man readlink` for more info
# the path to combined build
export RDK_PROJECT_ROOT_PATH=${RDK_PROJECT_ROOT_PATH-`readlink -m ..`}
export COMBINED_ROOT=$RDK_PROJECT_ROOT_PATH

# path to build script (this script)
export RDK_SCRIPTS_PATH=${RDK_SCRIPTS_PATH-`readlink -m $0 | xargs dirname`}

# path to components sources and target
export RDK_SOURCE_PATH=${RDK_SOURCE_PATH-`readlink -m .`}
export RDK_TARGET_PATH=${RDK_TARGET_PATH-$RDK_SOURCE_PATH}

# fsroot and toolchain (valid for all devices)
export RDK_FSROOT_PATH=${RDK_FSROOT_PATH-`readlink -m $RDK_PROJECT_ROOT_PATH/sdk/fsroot/ramdisk`}
export RDK_TOOLCHAIN_PATH=${RDK_TOOLCHAIN_PATH-`readlink -m $RDK_PROJECT_ROOT_PATH/sdk/toolchain/staging_dir`}


# default component name
export RDK_COMPONENT_NAME=${RDK_COMPONENT_NAME-`basename $RDK_SOURCE_PATH`}
export RDK_DIR=$RDK_PROJECT_ROOT_PATH

if [ "$XCAM_MODEL" == "SCHC2" ]; then
. ${RDK_PROJECT_ROOT_PATH}/build/components/amba/sdk/setenv2
else
. ${RDK_PROJECT_ROOT_PATH}/build/components/sdk/setenv2
fi


# parse arguments
INITIAL_ARGS=$@

function usage()
{
    set +x
    echo "Usage: `basename $0` [-h|--help] [-v|--verbose] [action]"
    echo "    -h    --help                  : this help"
    echo "    -v    --verbose               : verbose output"
    echo "    -p    --platform  =PLATFORM   : specify platform for rdklogger"
    echo
    echo "Supported actions:"
    echo "      configure, clean, build (DEFAULT), rebuild, install"
}

# options may be followed by one colon to indicate they have a required argument
if ! GETOPT=$(getopt -n "build.sh" -o hvp: -l help,verbose,platform: -- "$@")
then
    usage
    exit 1
fi

eval set -- "$GETOPT"

while true; do
  case "$1" in
    -h | --help ) usage; exit 0 ;;
    -v | --verbose ) set -x ;;
    -p | --platform ) CC_PLATFORM="$2" ; shift ;;
    -- ) shift; break;;
    * ) break;;
  esac
  shift
done

ARGS=$@


# component-specific vars
export FSROOT=${RDK_FSROOT_PATH}
export CFLAGS="-O3 -g -Wno-error -fPIC -DRDKC"

# functional modules
function configure()
{
    if [ "$XCAM_MODEL" == "XHC3" ]; then
        if [ -f $RDK_PATCHES/wifi-hal-gen-configure.patch ] && [ ! -f $RDK_PATCHES/.generic-wifi-hal_configure.patched ]; then
            cd $RDK_PROJECT_ROOT_PATH/wifi-hal-generic/
            cp $RDK_PATCHES/wifi-hal-gen-configure.patch .
            patch < wifi-hal-gen-configure.patch
            touch $RDK_PATCHES/.generic-wifi-hal_configure.patched
            cd -
        fi
    fi
   if [ "$XCAM_MODEL" == "XHB1" ] || [ "$XCAM_MODEL" == "XHC3" ]; then
        pd=`pwd`
        cd ${RDK_SOURCE_PATH}
        aclocal -I cfg
        libtoolize --automake
        automake --foreign --add-missing
        rm -f configure
        autoconf
        echo "  CONFIG_MODE = $CONFIG_MODE"
        configure_options=" "
	if [ "$XCAM_MODEL" == "XHC3" ]; then
	configure_options=" --host=arm-linux --target=arm-linux"
	else
        configure_options=" --host=aarch64-linux --target=aarch64"
	fi        
	configure_options="$configure_options --enable-shared"
        generic_options="$configure_options"
         
        export ac_cv_func_malloc_0_nonnull=yes
        export ac_cv_func_memset=yes
        export LDFLAGS+="-L${RDK_FSROOT_PATH}/usr/lib -llog4c -lrdkloggers -lwpa_client"
	echo Hi $CFLAGS
        export CFLAGS+=" --std=c99 -D_POSIX_C_SOURCE=199309L -I${RDK_SOURCE_PATH}/include -I${RDK_PROJECT_ROOT_PATH}/opensource/include/wpa_supplicant -I${RDK_PROJECT_ROOT_PATH}/rdklogger/include -I${RDK_FSROOT_PATH}/usr/include"
        export libwifihal_la_LDFLAGS=" $libwifihal_la_LDFLAGS -L${RDK_SOURCE_PATH}/usr/lib -lwpa_client -L${RDK_FSROOT_PATH}/usr/lib -lrdkloggers"
        autoreconf
        ./configure $configure_options
        cd $pd
   else
	true
   fi

}

function clean()
{
 if [ "$XCAM_MODEL" == "XHB1" ] || [ "$XCAM_MODEL" == "XHC3" ]; then

   pd=`pwd`
    dnames="${RDK_SOURCE_PATH}"
    for dName in $dnames
    do
        cd $dName
        if [ -f Makefile ]; then
                make distclean
        fi
        rm -f configure;
        rm -rf aclocal.m4 autom4te.cache config.log config.status libtool
        find . -iname "Makefile.in" -exec rm -f {} \;
        find . -iname "Makefile" | xargs rm -f
        ls cfg/* | grep -v "Makefile.am" | xargs rm -f
        cd $pd
    done
 else
	true
 fi
}

function build()
{
 if [ "$XCAM_MODEL" == "XHB1" ] || [ "$XCAM_MODEL" == "XHC3" ]; then

 cd ${RDK_SOURCE_PATH}
    export LDFLAGS="$LDFLAGS -L${RDK_SDROOT}/usr/lib -lwpa_client -L${RDK_SDROOT}/usr/lib -L${RDK_SDROOT}/usr/local/lib ${LOG4C_LIBS} -lrdkloggers"
    export CFLAGS="$CFLAGS --std=c99 -I${RDK_SOURCE_PATH}/include -I${RDK_PROJECT_ROOT_PATH}/opensource/include/wpa_supplicant -I${RDK_PROJECT_ROOT_PATH}/rdklogger/include -I${RDK_FSROOT_PATH}/usr/include "
    export libwifihal_la_LDFLAGS=" $libwifihal_la_LDFLAGS -L${RDK_FSROOT_PATH}/usr/lib -lwpa_client -L${RDK_SDROOT}/usr/lib -L${RDK_SDROOT}/usr/local/lib -lrdkloggers"
    if [ -f $RDK_PATCHES/fix-testwifi-wifi-hal-gen.patch ] && [ ! -f $RDK_PATCHES/.generic-wifi-hal.patched ]; then
      cd $RDK_PROJECT_ROOT_PATH/generic/wifi-hal/test
      cp $RDK_PATCHES/fix-testwifi-wifi-hal-gen.patch .
      patch < fix-testwifi-wifi-hal-gen.patch
      touch $RDK_PATCHES/.generic-wifi-hal.patched
      cd -
    fi
    time make
 else
	true
 fi
}

function rebuild()
{
    clean
    configure
    build
}

function install()
{
    cd ${RDK_SOURCE_PATH}/include
    cp -r wifi_ap_hal.h wifi_client_hal.h wifi_common_hal.h ${RDK_FSROOT_PATH}/usr/include
    mkdir -p ${RDK_SDROOT}/usr/include/wifi-generic/
    cp -r wifi_ap_hal.h wifi_client_hal.h wifi_common_hal.h ${RDK_SDROOT}/usr/include/wifi-generic/
 
 if [ "$XCAM_MODEL" == "XHB1" ] || [ "$XCAM_MODEL" == "XHC3" ]; then
    cd ${RDK_SOURCE_PATH}
    mkdir -p ${RDK_SDROOT}/usr/lib/wifi-generic
    if [ -f  ${RDK_SDROOT}/usr/lib/libwifihal.so ]; then
      rm -rf ${RDK_SDROOT}/usr/lib/libwifihal.so*
      rm -rf ${RDK_SDROOT}/usr/local/lib/libwifihal.so*
    fi
    if [ -f ${RDK_FSROOT_PATH}/usr/lib/libwifihal.so ]; then
      rm -rf ${RDK_FSROOT_PATH}/usr/lib/libwifihal.so*
    fi
    cp -r ${RDK_SOURCE_PATH}/src/.libs/libwifihal.so* ${RDK_SDROOT}/usr/lib/wifi-generic/
    cp -r ${RDK_SOURCE_PATH}/src/.libs/libwifihal.so* ${RDK_SDROOT}/usr/lib/
    mkdir -p ${RDK_SDROOT}/usr/bin/wifi-generic/ 
    cp -r ${RDK_SOURCE_PATH}/test/testwifi ${RDK_SDROOT}/usr/bin/wifi-generic/
    make install DESTDIR=${RDK_SDROOT}
 fi
}


# run the logic

#these args are what left untouched after parse_args
HIT=false

for i in "$ARGS"; do
    case $i in
        configure)  HIT=true; configure ;;
        clean)      HIT=true; clean ;;
        build)      HIT=true; build ;;
        rebuild)    HIT=true; rebuild ;;
        install)    HIT=true; install ;;
        *)
            #skip unknown
        ;;
    esac
done

# if not HIT do build by default
if ! $HIT; then
  build
fi
