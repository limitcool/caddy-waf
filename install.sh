#!/bin/bash
set -e
git clone https://github.com/fabriziosalmi/caddy-waf.git
cd caddy-waf
go mod tidy
go get -v github.com/fabriziosalmi/caddy-waf github.com/caddyserver/caddy/v2 github.com/oschwald/maxminddb-golang
wget https://git.io/GeoLite2-Country.mmdb
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./
caddy fmt --overwrite
./caddy run
