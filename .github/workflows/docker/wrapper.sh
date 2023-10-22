#!/bin/bash

export HEADLESS=y

if [[ $INSTALL_TYPE == "FULL" ]]; then
    export BROTLI=y
    export HEADERMOD=y
    export GEOIP=y
    export FANCYINDEX=y
    export CACHEPURGE=y
    export WEBDAV=y
    export VTS=y
    export RTMP=y
    export zstd=y
    export MODSEC=n
fi

bash -x ../../nginx-autoinstall.sh