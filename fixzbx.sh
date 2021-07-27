#!/bin/bash
#TLSConnect=psk
#TLSAccept=psk
#TLSPSKFile=/etc/zabbix/zabbix_agent.psk
#TLSPSKIdentity=ZBXDATAONE
FILE=/etc/zabbix/zabbix_agentd.conf
PSKID=$( sed -En "s/^[^#]*TLSPSKIdentity=(.*)/\1/p" $FILE )
HOSTNAME=$( sed -En "s/^[^#]*Hostname=(.*)/\1/p" $FILE )
SERVER=$( sed -En "s/^[^#]*Server=(.*)/\1/p" $FILE )
#
sed -i.bak -E "/^[^#]*TLSPSKFile=/d" $FILE
sed -i -E "/^[^#]*TLSAccept=/d" $FILE
sed -i -E "/^[^#]*TLSConnect=/d" $FILE
sed -i -E "/^[^#]*Hostname=/d" $FILE
sed -i -E "/^[^#]*Server=/d" $FILE
sed -i -E "/^[^#]*ServerActive=/d" $FILE
sed -i -E "/^[^#]*TLSPSKIdentity=/d" $FILE
#
sed -i -E "s/^#.*TLSConnect=.*/TLSConnect=psk/" $FILE
sed -i -E "s/^#.*TLSAccept=.*/TLSAccept=psk/" $FILE
sed -i -E "s/^#.*TLSPSKFile=.*/TLSPSKFile=\/etc\/zabbix\/zabbix_agent.psk/" $FILE
sed -i -E "s/^#+[[:space:]]Server=/Server=${SERVER}/" $FILE
sed -i -E "s/^#+[[:space:]]ServerActive=/ServerActive=${SERVER}/" $FILE
sed -i -E "s/^#+[[:space:]]Hostname=/Hostname=${HOSTNAME}/" $FILE
sed -i -E "s/^#+[[:space:]]TLSPSKIdentity=/TLSPSKIdentity=${PSKID}/" $FILE
