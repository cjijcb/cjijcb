#!/bin/bash
echo -n "Enter the Zabbix server IP:"
read ZBXIP 
rpm -Uvh https://repo.zabbix.com/zabbix/5.0/rhel/$(rpm -E %{rhel})/x86_64/zabbix-release-5.0-1.el$(rpm -E %{rhel}).noarch.rpm
#
sed -i.bak \
"s/^Server=.*/${ZBXIP}/; \
s/^ServerActive=.*/${ZBXIP}/; \
s/.*HostMetadata=.*/HostMetadata=Linux/; \
s/.*HostnameItem=.*/HostnameItem=system.hostname/; \
s/Hostname=[[:alpha:]].*/#&/" \
/etc/zabbix/zabbix_agentd.conf
#
sudo systemctl restart zabbix-agent
sudo systemctl enable zabbix-agent
