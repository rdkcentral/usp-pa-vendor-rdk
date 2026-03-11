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
    pkg-config \
    valgrind \
    psmisc \
    lcov

# Environment variables from Yocto SDK for default compiler flags
ENV CFLAGS=" -Os -pipe -g -feliminate-unused-debug-types "
ENV CXXFLAGS=" -Os -pipe -g -feliminate-unused-debug-types "
ENV LDFLAGS="-Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed"

WORKDIR /work

# obuspa
# Minimum version is v10.0.9 to install header files in the proper location
ARG OBUSPA_REF="7262a0eb579cee12dfda956d036f8ec70a343b0c"
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
COPY rbus /work/rbus
RUN cd /work/rbus && \
    cmake -B build \
        -DCMAKE_INSTALL_PREFIX="/usr/local" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_C_FLAGS="-I/usr/local/include" \
        -DBUILD_FOR_DESKTOP=ON \
        -DMSG_ROUNDTRIP_TIME=ON \
        -DBUILD_RBUS_SAMPLE_APPS=ON \
        -DBUILD_RBUS_TEST_APPS=OFF  && \
    make VERBOSE=1 -C build install && \
    cp /work/rbus/build/deps/src/msgpack/libmsgpackc.so* /usr/local/lib/ && \
    cp /work/rbus/build/deps/src/cjson/libcjson.so* /usr/local/lib/ && \
    rm -rf /work/rbus

# usp-pa-vendor-rdk
COPY usp-pa-vendor-rdk /work/usp-pa-vendor-rdk
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

# Create symlink for UspPA as requested by user
RUN ln -s /usr/local/bin/obuspa /usr/local/bin/UspPA

COPY start_services.sh /usr/local/bin/start_services.sh
RUN chmod +x /usr/local/bin/start_services.sh

# Ensure log files exist for tail
RUN touch /var/log/rtrouted.log /var/log/obuspa.log

# Ensure etc directory exists for vendor config
RUN mkdir -p /etc/usp-pa && chmod 777 /etc/usp-pa

ENTRYPOINT [ "/usr/local/bin/start_services.sh" ]
