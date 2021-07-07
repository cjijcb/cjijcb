#!/bin/bash
RD='\033[1;31m'
GRN='\033[1;32m'
PRPL='\033[1;35m'
NC='\033[0m'
echo -n "Set a TLS PSK Identity for this agent (it should be unique e.g. ZBX01):"
read TLS_PSK_ID
sudo openssl rand -hex 32 > /etc/zabbix/zabbix_agent.psk && \
sudo chown zabbix:zabbix /etc/zabbix/zabbix_agent.psk && \
sudo chmod 700 /etc/zabbix/zabbix_agent.psk && \
#
echo -e \
"TLSConnect=psk\n\
TLSAccept=psk\n\
TLSPSKFile=/etc/zabbix/zabbix_agent.psk\n\
TLSPSKIdentity=${TLS_PSK_ID}" \
>> /etc/zabbix/zabbix_agentd.conf && \
sudo systemctl restart zabbix-agent && \
echo -e "${GRN}PSK encryption successfully enabled. PSK: ${RD}$( cat /etc/zabbix/zabbix_agent.psk )${NC}"
