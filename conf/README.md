# Configurations files

## PageSpeed

Add this in your http block:

```nginx
pagespeed on;
pagespeed StatisticsPath /ngx_pagespeed_statistics;
pagespeed GlobalStatisticsPath /ngx_pagespeed_global_statistics;
pagespeed MessagesPath /ngx_pagespeed_message;
pagespeed ConsolePath /pagespeed_console;
pagespeed AdminPath /pagespeed_admin;
pagespeed GlobalAdminPath /pagespeed_global_admin;
# Needs to exist and be writable by nginx.
# Use tmpfs for best performance.
pagespeed FileCachePath /var/ngx_pagespeed_cache;
```

## Brotli

Add this in your http block :

```nginx
brotli on;
brotli_static on;
brotli_buffers 16 8k;
brotli_comp_level 6;
brotli_types *;
```

## LibreSSL / OpenSSL 1.1+

You can now use ChaCha20 in addition to AES. Add this in your server block:

```nginx
ssl_ciphers EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
```

You can also use more secure curves :

```nginx
ssl_ecdh_curve X25519:P-521:P-384:P-256;
```

## TLS 1.3

TLS 1.3 needs special ciphers.

```nginx
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:TLS-AES-128-GCM-SHA256:EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
```

TLS- can be TLS13-.

## GeoIP 2

See <https://github.com/leev/ngx_http_geoip2_module#example-usage>

## GOSTNGX

```nginx
-
```

## ModSecurity

```nginx
server {
    listen 80;
 modsecurity on;
 modsecurity_rules_file /etc/nginx/modsec/main.conf;

# If you have proxy
    location / {     
     proxy_pass http://192.168.x.x;
    }
}
```

## OWASP rules

/etc/nginx/modsec/main.conf:

```nginx
# OWASP CRS v3 rules
Include /etc/nginx/modsec/coreruleset-3.3.4/crs-setup.conf
Include /etc/nginx/modsec/coreruleset-3.3.4/rules/*.conf
```

## NGXWAF
Configuration Guide, Test module nginx -V and nginx -V &  https://docs.addesp.com/ngx_waf/guide/test.html#quick-test

```nginx
http {
    waf_zone name=waf size=20m;
    ...
    server {
        ...
        # on means enabled, off means disabled.
        waf on;

        # The absolute path to the directory where the rule file is located, must end with /.
        waf_rule_path /usr/local/src/ngx_waf/assets/rules/;

        # Firewall working mode, STD indicates standard mode.
        waf_mode STD;

        # CC defense parameter, 1000 requests per minute limit, 
        # block the corresponding ip for 60 minutes after exceeding the limit.
        waf_cc_deny on rate=1000r/m duration=60m zone=waf:cc;

        # Cache detection results for up to 50 detection targets, 
        # effective for all detections 
        # except IP black and white list detection, CC protection and POST detection.
        waf_cache on capacity=50;
        ...
    }
    ...
}
```