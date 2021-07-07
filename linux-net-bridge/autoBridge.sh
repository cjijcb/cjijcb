#!/bin/bash
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
#
IPV4=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4[[:space:]](.*)\/.*/\1/p}" ) && \
PRFX=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4.*\/(.*)/\1/p}" ) && \
GTWY=$( ip route | sed -E -n "s/default via (.*) dev.*/\1/p" ) && \
DNS=$( nmcli | sed -E -n "/DNS configuration:/,/servers:/{/servers:/p}" | cut -d' ' -f2- | sed "s/[[:space:]]/,/g" ) && \
ETH=$(  nmcli | sed -E -n "s/.*: connected to (.*)/\1/p" ) && \
nmcli con add type bridge ifname bridge0 con-name bridge0 && \
nmcli con mod bridge0 ipv4.addr ${IPV4}/${PRFX} && \
nmcli con mod bridge0 ipv4.gateway ${GTWY} && \
nmcli con mod bridge0 ipv4.method manual && \
nmcli con mod bridge0 ipv4.dns ${DNS} && \
nmcli con mod bridge0 bridge.stp no && \
nmcli con add type ethernet slave-type bridge ifname ${ETH} master bridge0 && \
nmcli con mod bridge0 connection.autoconnect-slaves yes && \
nmcli con down ${ETH} && \
nmcli con up bridge0
