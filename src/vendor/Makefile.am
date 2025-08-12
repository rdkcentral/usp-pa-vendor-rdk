AM_CPPFLAGS = \
    -I$(SYSROOT)$(includedir)/obuspa \
    -I$(SYSROOT)$(includedir)/obuspa/core \
    -I$(SYSROOT)$(includedir)/obuspa/include \
    -I$(SYSROOT)$(includedir)/obuspa/libjson \
    -I$(SYSROOT)$(includedir)/obuspa/protobuf-c \
    -I$(SYSROOT)$(includedir)/rbus \
    -I$(includedir)/rbus

AM_CFLAGS = -Wall -Wfatal-errors
AM_LDFLAGS =

# Compiler hardening flags
AM_CFLAGS += $(CFLAGS_HARDENING)
AM_LDFLAGS += $(LDFLAGS_HARDENING)

libexecmoduledir = $(libexecdir)
libexecmodule_LTLIBRARIES = usp-pa-vendor-rdk.la

usp_pa_vendor_rdk_la_SOURCES = vendor.c

usp_pa_vendor_rdk_la_CPPFLAGS = \
    $(AM_CPPFLAGS) \
    -Werror \
    -Werror=unused-value \
    -Werror=format \
    -Winit-self \
    -Wparentheses -Werror=parentheses \
    -Wuninitialized -Werror=uninitialized -Werror=maybe-uninitialized -Wpointer-arith

usp_pa_vendor_rdk_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -module -shared -export-dynamic
usp_pa_vendor_rdk_la_LDFLAGS += -lrbus
