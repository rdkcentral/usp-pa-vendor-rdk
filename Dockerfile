FROM debian:12

# Install build dependencies
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    git \
    libcurl4-openssl-dev \
    libtool \
    libmosquitto-dev \
    libsqlite3-dev \
    libssl-dev \
    libz-dev \
    pkg-config

# Environment variables from Yocto SDK for default compiler flags
ENV CFLAGS=" -Os -pipe -g -feliminate-unused-debug-types "
ENV CXXFLAGS=" -Os -pipe -g -feliminate-unused-debug-types "
ENV LDFLAGS="-Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed"

WORKDIR /work

# obuspa
# Minimum version is v10.0.9 to install header files in the proper location
ARG OBUSPA_REF="cd71ce1fe34e782b6b417e9eee46f861060301bf"
RUN git clone https://github.com/BroadbandForum/obuspa && \
    cd obuspa && \
    git checkout "$OBUSPA_REF" && \
    autoreconf --force --install && \
    mkdir -p build && \
    cd build && \
    ../configure \
        CFLAGS="$CFLAGS" \
        LDFLAGS="$LDFLAGS" \
        --prefix="/usr/local" \
        --disable-websockets \
        && \
    make install-strip -j && \
    rm -rf /work/obuspa

# rbus
ARG RBUS_VERSION="v2.0.11"
RUN git clone https://github.com/rdkcentral/rbus.git -b "$RBUS_VERSION" && \
    cd rbus && \
    cmake -B build \
        -DCMAKE_INSTALL_PREFIX="/usr/local" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_C_FLAGS="-I/usr/local/include" \
        -DBUILD_FOR_DESKTOP=ON \
        -DMSG_ROUNDTRIP_TIME=ON \
        -DBUILD_RBUS_SAMPLE_APPS=OFF \
        -DBUILD_RBUS_TEST_APPS=OFF  && \
    make VERBOSE=1 -C build install -j && \
    rm -rf /work/rbus

# usp-pa-vendor-rdk
COPY . /work/usp-pa-vendor-rdk
RUN cd /work/usp-pa-vendor-rdk/src/vendor && \
    autoreconf --force --install && \
    mkdir -p build && \
    cd build && \
    ../configure \
        CFLAGS="$CFLAGS" \
        LDFLAGS="$LDFLAGS" \
        --prefix="/usr/local" && \
    make install-strip -j && \
    rm -rf /work/usp-pa-vendor-rdk

ENTRYPOINT [ "/bin/bash" ]
