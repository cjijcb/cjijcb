#!/bin/bash
GRN='\033[1;32m'
NC='\033[0m'
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
echo "detecting existing bridge interface..."
ALL_CON_NAME=( $( nmcli con show | sed -En "/NAME/,$ {/NAME/! s/([^[:space:]]+)[[:space:]]+.*/\1/p}" ) ) 
for V in "${ALL_CON_NAME[@]}"
do
  SLAVE_TYPE=$( nmcli con show "$V" | sed -En "s/connection\.slave-type:[[:space:]]+([^[:space:]].*)/\1/p" )
  if [ "$SLAVE_TYPE" = "bridge" ]; then
    PORT_BRIDGE_CON_NAME=$V
    SLAVE_ETHERTNET_DEV_NAME=$( nmcli con show "$PORT_BRIDGE_CON_NAME" | sed -En "s/connection\.interface-name:[[:space:]]+([^[:space:]].*)/\1/p" ) > /dev/null 2>&1
    MASTER_BRIDGE_DEV_NAME=$( nmcli con show "$PORT_BRIDGE_CON_NAME" | sed -En "s/connection\.master:[[:space:]]+([^[:space:]].*)/\1/p" ) > /dev/null 2>&1
    MASTER_BRIDGE_CON_NAME=$( nmcli dev show "$MASTER_BRIDGE_DEV_NAME" | sed -En "s/GENERAL\.CONNECTION:[[:space:]]+([^[:space:]]+.*)/\1/p" ) > /dev/null 2>&1
  break
  fi
done
#
if [ -n "$MASTER_BRIDGE_CON_NAME" ]; then 
  echo "deleting existing brigde interface..."
  nmcli con del $PORT_BRIDGE_CON_NAME 1> /dev/null
  nmcli con del $MASTER_BRIDGE_CON_NAME 1> /dev/null
  nmcli dev con $SLAVE_ETHERTNET_DEV_NAME 1> /dev/null
fi
#
if [ "$1" != "-d" ]; then
  echo "detecting ip..."
  IPV4=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4[[:space:]](.*)\/.*/\1/p}" ) && \
  echo "detecting subnetmask..."
  PRFX=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4.*\/(.*)/\1/p}" ) && \
  echo "detecting gateway..."
  GTWY=$( ip route | sed -E -n "s/default via (.*) dev.*/\1/p" ) && \
  echo "detecting dns..."
  DNS=$( nmcli | sed -E -n "/DNS configuration:/,/servers:/{/servers:/p}" | cut -d' ' -f2- | sed "s/[[:space:]]/,/g" ) && \
  echo "detecting network interface..."
  ETH=$(  nmcli | sed -E -n "s/.*: connected to (.*)/\1/p" ) && \
  echo "creating bridge interface..."
  nmcli con add type bridge ifname bridge0 con-name bridge0 > /dev/null && \
  echo "configuring bridge interface..."
  nmcli con mod bridge0 ipv4.addr ${IPV4}/${PRFX} 1> /dev/null && \
  nmcli con mod bridge0 ipv4.gateway ${GTWY} 1> /dev/null && \
  nmcli con mod bridge0 ipv4.method manual 1> /dev/null && \
  nmcli con mod bridge0 ipv4.dns ${DNS} 1> /dev/null && \
  nmcli con mod bridge0 bridge.stp no 1> /dev/null && \
  nmcli con add type ethernet slave-type bridge ifname ${ETH} master bridge0 > /dev/null 2>&1 && \
  nmcli con mod bridge0 connection.autoconnect-slaves yes > /dev/null 2>&1 && \
  echo "enabling bridge interface..."
  nmcli con down ${ETH} 1> /dev/null && \
  nmcli con up bridge0 1> /dev/null
  echo -e "${GRN}bridge interface successfully configured.${NC}"
fi 
