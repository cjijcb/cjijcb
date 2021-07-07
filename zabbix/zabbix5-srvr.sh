#!/bin/bash
RD='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
NC='\033[0m'
#
echo -n -e "Set a ${GRN}root ${RD}password${NC} for ${GRN}mariaDB${NC}:"
read ROOTPASS
if [[ -z "$ROOTPASS" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
echo -n -e "Set a ${GRN}Zabbix database ${RD}password${NC}:"
read ZBXPASS
if [[ -z "$ZBXPASS" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
setenforce 0 && \
sed -i.orig 's/^SELINUX=.*/SELINUX=permissive/g' /etc/selinux/config
rpm -Uvh https://repo.zabbix.com/zabbix/5.0/rhel/8/x86_64/zabbix-release-5.0-1.el8.noarch.rpm
yum clean all > /devn/null 2>&1 
yum -y install zabbix-server-mysql zabbix-web-mysql zabbix-apache-conf zabbix-agent mariadb-server && \
systemctl start mariadb && \
systemctl enable mariadb && \
#
mysql_secure_installation <<EOF || exit
${NULL}
y
${ROOTPASS}
${ROOTPASS}
y
y
y
y
EOF
#
mysql --user="root" --password="${ROOTPASS}" --execute="create database zabbix character set utf8 collate utf8_bin;" && \
mysql --user="root" --password="${ROOTPASS}" --execute="grant all privileges on zabbix.* to zabbix@localhost identified by \"${ZBXPASS}\";" && \
mysql --user="root" --password="${ROOTPASS}" zabbix --execute="set global innodb_strict_mode='OFF';" && \
echo -e "${GRN}Importing database shema for Zabbix server. It could take up to 5 minutes...${NC}" && \
zcat /usr/share/doc/zabbix-server-mysql*/create.sql.gz | mysql --user="zabbix" --password="${ZBXPASS}" zabbix &&\
mysql --user="root" --password="${ROOTPASS}" zabbix --execute="set global innodb_strict_mode='ON';" && \
#
sed -i.orig "s/.*DBPassword=.*/DBPassword=${ZBXPASS}/"  /etc/zabbix/zabbix_server.conf && \
#
systemctl restart zabbix-server zabbix-agent
systemctl enable zabbix-server zabbix-agent
sed -i.orig "s/.*php_value\[date\.timezone\].*/php_value[date.timezone] = Asia\/Manila /" /etc/php-fpm.d/zabbix.conf && \
#
systemctl restart httpd php-fpm
systemctl enable httpd php-fpm
#
