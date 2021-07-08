#!/bin/bash
GRN='\033[1;32m'
NC='\033[0m'
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
#
echo -n "Enter the Zabbix server IP:"
read ZBXIP 
echo -n "Set hostname for this Zabbix agent or just press enter for autogenaration:"
read AZBX_HOSTNAME
rpm -Uvh https://repo.zabbix.com/zabbix/5.0/rhel/$(rpm -E %{rhel})/x86_64/zabbix-release-5.0-1.el$(rpm -E %{rhel}).noarch.rpm
yum -y install zabbix-agent
#
sed -i \
"s/^Server=.*/Server=${ZBXIP}/; \
s/^ServerActive=.*/ServerActive=${ZBXIP}/; \
s/.*HostMetadata=.*/HostMetadata=Linux/; \
s/.*HostnameItem=.*/HostnameItem=system.hostname/" \
/etc/zabbix/zabbix_agentd.conf
#
if [[ -z "${AZBX_HOSTNAME}" ]]; then
  sed -i "s/Hostname=[[:alpha:]].*/#&/" /etc/zabbix/zabbix_agentd.conf
else
  sed -i "s/Hostname=[[:alpha:]].*/Hostname=${AZBX_HOSTNAME}/" /etc/zabbix/zabbix_agentd.conf
fi
#
sudo systemctl restart zabbix-agent
sudo systemctl enable zabbix-agent
echo -e "${GRN}Zabbix Agent 5.0 Successfully Installed.${NC}"
