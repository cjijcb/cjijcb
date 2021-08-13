#!/bin/bash
curl -s -O https://repo.zabbix.com/zabbix/5.4/rhel/8/x86_64/zabbix-release-5.4-1.el8.noarch.rpm
rpm -Uvh ./zabbix-release-5.4-1.el8.noarch.rpm
yum upgrade zabbix-server-mysql zabbix-web-mysql zabbix-agent -y
