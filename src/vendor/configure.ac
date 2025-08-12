# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])

m4_define([VERSION_FROM_GIT], m4_esyscmd_s([
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git describe --tags --always --dirty
    else
        echo "0.0.0"
    fi | tr -d '\n'
]))

AC_INIT([usp-pa-vendor-rdk], [m4_defn([VERSION_FROM_GIT])])
AC_MSG_NOTICE([Version from git: ]m4_defn([VERSION_FROM_GIT]))
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects -Wall -Werror -Wno-portability])
AC_CONFIG_MACRO_DIR([m4])
LT_PREREQ([2.2])

# Define _GNU_SOURCE if using GNU versions of strerror_r and dladdr()
AC_USE_SYSTEM_EXTENSIONS

# Configure use of libtool
LT_INIT([shared disable-static])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Use sysroot if provided - override default no to empty string
AC_ARG_WITH([sysroot],
    [AS_HELP_STRING([--with-sysroot=DIR], [Specify a custom sysroot for cross-compilation])],
    [SYSROOT=$with_sysroot], [SYSROOT=""])
AS_IF([test "x$SYSROOT" = "xno"], [SYSROOT=""])

# Pass sysroot to Makefile
AC_SUBST(SYSROOT)

AC_ARG_ENABLE(hardening, [AS_HELP_STRING([--enable-hardening], [enable compiler hardening flags])],,enable_hardening=no)

AS_IF([test "x$enable_hardening" = "xyes"], [
    # Enable compiler hardening flags - do not touch CFLAGS or LDFLAGS directly
    CFLAGS_HARDENING="$CFLAGS_HARDENING -fstack-protector-strong"
    CFLAGS_HARDENING="$CFLAGS_HARDENING -fPIE"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -pie"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,relro"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,now"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,noexecstack"

    # Fortify requires optimization
    CFLAGS_HARDENING="$CFLAGS_HARDENING -O2 -D_FORTIFY_SOURCE=2"
    AC_SUBST([CFLAGS_HARDENING])
    AC_SUBST([LDFLAGS_HARDENING])
])

# Find out if GNU or XSI versions of strerror_r are being used
AC_FUNC_STRERROR_R

# Check for glibc specific functionality, setting HAVE_MALLINFO and HAVE_EXECINFO_H defines in the generated makefiles
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([execinfo.h])
AC_CHECK_FUNCS([mallinfo])
AC_CHECK_FUNCS([mallinfo2])

# Needed to work with default vendor_defs.h (USP Broker and USP Service functionalities need UDS MTP)
AC_DEFINE([ENABLE_UDS], [1], [Enable UDS MTP Message support])

# Generate Makefiles
AC_CONFIG_FILES([Makefile])

# Finally, generate top-level config.status.
AC_OUTPUT
