#!/bin/bash

export HEADLESS=y

if [[ $INSTALL_TYPE == "FULL" ]]; then
    export PAGESPEED=y
    export BROTLI=y
    export HEADERMOD=y
    export GEOIP=y
    export FANCYINDEX=y
    export CACHEPURGE=y
    export WEBDAV=y
    export VTS=y
    export RTMP=y
    export HTTP3=n
    export NGXWAF=n
    export MODSEC=y
fi

bash -x ../../nginx-autoinstall.sh