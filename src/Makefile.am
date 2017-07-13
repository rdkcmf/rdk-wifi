SUBDIRS = 
lib_LTLIBRARIES=libwifihal.la
libwifihal_la_SOURCES=wifi_client_hal.c wifi_common_hal.c
libwifihal_la_LDFLAGS=-lwpa_client

bin_PROGRAMS= wifi_hal_test
wifi_hal_test_SOURCES = wifi_hal_test.c
wifi_hal_test_LDADD = libwifihal.la 
wifi_hal_test_LDFLAGS=-lpthread
