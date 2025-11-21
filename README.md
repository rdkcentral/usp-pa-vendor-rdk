usp-pa-vendor-rdk
-----------------

This repository specializes the Open Broadband-User Services Platform-Agent (OB-USP-Agent) for use with RDK.

RDK's USP protocol agent (usp-pa) is built from OB-USP-Agent and this repository.

User Services Platform (USP) is a remote management and control protocol:
https://usp.technology/

OB-USP-AGENT is a system daemon providing a User Services Platform (USP) Agent:
https://github.com/BroadbandForum/obuspa

## Docker Build

There is a Dockerfile to test building usp-pa-vendor-rdk along with obuspa and rbus. The binaries are installed to `/usr/local`.

```
docker build -t usp-pa-vendor-rdk .
```

The obuspa and rbus versions can be overriden with build arguments:
```
docker build \
    --build-arg "OBUSPA_REF=cd71ce1fe34e782b6b417e9eee46f861060301bf" \
    --build-arg "RBUS_VERSION=v2.0.11" \
    -t usp-pa-vendor-rdk \
    .
```
