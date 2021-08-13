#!/bin/bash
RD='\033[1;31m'
GRN='\033[1;32m'
PRPL='\033[1;35m'
NC='\033[0m'
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
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
rpm -Uvh https://repo.zabbix.com/zabbix/5.4/rhel/8/x86_64/zabbix-release-5.4-1.el8.noarch.rpm
yum clean all > /dev/null 2>&1 
#
yum -y install \
zabbix-server-mysql \
zabbix-web-mysql \
zabbix-apache-conf \
zabbix-agent \
mariadb-server \
policycoreutils-python-utils && \
#
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
echo -e "${PRPL}Importing database schema for Zabbix server. It could take up to 5 minutes...${NC}";
zcat /usr/share/doc/zabbix-sql-scripts/mysql/create.sql.gz | mysql --user="zabbix" --password="${ZBXPASS}" zabbix &&\
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
#~~~OPTIMIZATION~~~#
#
curl --progress-bar -O https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/zabbix/zbx_db_partitiong.sql && \
echo "Creating MySQL partitions on History and Events tables..."
mysql --user="zabbix" --password="${ZBXPASS}" zabbix < zbx_db_partitiong.sql && \
sed -i "/\[mysqld\]/ a event_scheduler = ON" /etc/my.cnf.d/mariadb-server.cnf && \
sudo systemctl restart mysql && \
mysql --user="zabbix" --password="${ZBXPASS}" zabbix --execute="CREATE EVENT zbx_partitioning ON SCHEDULE EVERY 12 HOUR DO CALL partition_maintenance_all('zabbix');" && \
echo -e \
"StartPollers=100\n\
StartPollersUnreachable=50\n\
StartPingers=50\n\
StartTrappers=10\n\
StartDiscoverers=15\n\
StartPreprocessors=15\n\
StartHTTPPollers=5\n\
StartAlerters=5\n\
StartTimers=2\n\
StartEscalators=2\n\
CacheSize=128M\n\
HistoryCacheSize=64M\n\
HistoryIndexCacheSize=32M\n\
TrendCacheSize=32M\n\
ValueCacheSize=256M" \
>> /etc/zabbix/zabbix_server.conf
#
cat > /etc/my.cnf.d/10_my_tweaks.cnf <<EOF
[mysqld]
max_connections = 404
innodb_buffer_pool_size = 800M
innodb-log-file-size = 128M
innodb-log-buffer-size = 128M
innodb-file-per-table = 1
innodb_buffer_pool_instances = 8
innodb_old_blocks_time = 1000
innodb_stats_on_metadata = off
innodb-flush-method = O_DIRECT
innodb-log-files-in-group = 2
innodb-flush-log-at-trx-commit = 2
tmp-table-size = 96M
max-heap-table-size = 96M
open_files_limit = 65535
max_connect_errors = 1000000
connect_timeout = 60
wait_timeout = 28800
EOF
#
sudo chown mysql:mysql /etc/my.cnf.d/10_my_tweaks.cnf
sudo chmod 644 /etc/my.cnf.d/10_my_tweaks.cnf
#
sudo systemctl stop zabbix-server
sudo systemctl stop mysql
sudo systemctl start mysql
sudo systemctl start zabbix-server
#
echo "Creating additional SELINUX policy for Zabbix..."
setsebool -P httpd_can_connect_zabbix 1
setsebool -P zabbix_can_network 1
setenforce 1 && sed -i 's/^SELINUX=.*/SELINUX=enforcing/g' /etc/selinux/config
grep "denied.*zabbix" /var/log/audit/audit.log | audit2allow -M zabbix_policy > /dev/null 2>&1
semodule -i zabbix_policy.pp
#
echo -e "${GRN}Zabbix Server 5.0 Successfully Installed.${NC}"
