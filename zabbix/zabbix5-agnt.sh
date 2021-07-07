#!/bin/bash
rpm -Uvh https://repo.zabbix.com/zabbix/5.0/rhel/$(rpm -E %{rhel})/x86_64/zabbix-release-5.0-1.el$(rpm -E %{rhel}).noarch.rpm
#
sed "s/^Server=.*/pooooooooooooooooo/" /etc/zabbix/zabbix_agentd.conf
sed "s/^ServerActive=.*/pooooooooooooooooo/" /etc/zabbix/zabbix_agentd.conf
sed "s/.*HostMetadata=.*/HostMetadata=Linux/" /etc/zabbix/zabbix_agentd.conf
sed "s/.*HostnameItem=.*/HostnameItem=system.hostname/" /etc/zabbix/zabbix_agentd.conf
sed "s/Hostname=[[:alpha:]].*/#&/" /etc/zabbix/zabbix_agentd.conf
sudo systemctl restart zabbix-agent
sudo systemctl enable zabbix-agent
#
