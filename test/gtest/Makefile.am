##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
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
##########################################################################

AM_CFLAGS = -I$(top_srcdir)/include 
AM_LDFLAGS = -lgtest -lpthread
check_PROGRAMS = wifi_gtest_suite
wifi_gtest_suite_SOURCES = gtest_main.cpp parser.cpp
wifi_gtest_suite_LDADD = $(top_builddir)/src/libwifihal.la 

TESTS = wifi_gtest_suite
TEST_SUITE_LOG = wifi_gtest_suite.log
TESTS_ENVIRONMENT = export GTEST_OUTPUT="xml:wifi_gtest_suite.xml";