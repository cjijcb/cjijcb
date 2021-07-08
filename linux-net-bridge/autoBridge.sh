#!/bin/bash
GRN='\033[1;32m'
NC='\033[0m'
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
#
echo "[1/8] detecting ip..."
IPV4=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4[[:space:]](.*)\/.*/\1/p}" ) && \
echo "[2/8] detecting subnetmask..."
PRFX=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4.*\/(.*)/\1/p}" ) && \
echo "[3/8] detecting gateway..."
GTWY=$( ip route | sed -E -n "s/default via (.*) dev.*/\1/p" ) && \
echo "[4/8] detecting dns..."
DNS=$( nmcli | sed -E -n "/DNS configuration:/,/servers:/{/servers:/p}" | cut -d' ' -f2- | sed "s/[[:space:]]/,/g" ) && \
echo "[5/8] detecting network interface..."
ETH=$(  nmcli | sed -E -n "s/.*: connected to (.*)/\1/p" ) && \
echo "[6/8] creating bridge interface..."
nmcli con add type bridge ifname bridge0 con-name bridge0 > /dev/null 2>&1 && \
echo "[7/8] configuring bridge interface..."
nmcli con mod bridge0 ipv4.addr ${IPV4}/${PRFX} > /dev/null 2>&1 && \
nmcli con mod bridge0 ipv4.gateway ${GTWY} > /dev/null 2>&1 && \
nmcli con mod bridge0 ipv4.method manual > /dev/null 2>&1 && \
nmcli con mod bridge0 ipv4.dns ${DNS} > /dev/null 2>&1 && \
nmcli con mod bridge0 bridge.stp no > /dev/null 2>&1 && \
nmcli con add type ethernet slave-type bridge ifname ${ETH} master bridge0 > /dev/null 2>&1 && \
nmcli con mod bridge0 connection.autoconnect-slaves yes > /dev/null 2>&1 && \
echo "[8/8] enabling bridge interface..."
nmcli con down ${ETH} > /dev/null 2>&1 && \
nmcli con up bridge0 > /dev/null 2>&1
echo -e "${GRN}bridge interface successfully configured.${NC}"
