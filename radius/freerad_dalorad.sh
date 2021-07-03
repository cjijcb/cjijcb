#!/bin/bash
#coloring
RD='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'
#
echo -e "Enter a new ${GRN}root ${RD}password${NC} for ${GRN}mariaDB${NC}:"
read rootPass
if [[ -z "$rootPass" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
echo -e "Enter a new ${GRN}radius database ${YLW}name${NC}:"
read radNameDB
if [[ -z "$radNameDB" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
echo -e "Enter a new ${GRN}radius database ${RD}password${NC}:"
read radPass
if [[ -z "$radPass" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
sudo yum -y install httpd && \
sudo systemctl start httpd && \
sudo systemctl enable --now httpd && \
sudo dnf -y install mariadb-server && \
sudo systemctl start mariadb && \
#
mysql_secure_installation <<EOF
$NULL
y
${rootPass}
${rootPass}
y
y
y
y
EOF
#
cat > /etc/yum.repos.d/ol8-epel.repo <<EOF
[ol8_developer_EPEL]
name= Oracle Linux \$releasever EPEL ($basearch)
baseurl=https://yum.oracle.com/repo/OracleLinux/OL8/developer/EPEL/\$basearch/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=1
EOF
#
sudo dnf makecache && \
sudo dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && \
sudo dnf install -y dnf-utils http://rpms.remirepo.net/enterprise/remi-release-8.rpm && \
sudo dnf -y module list php && \
sudo dnf -y module reset php && \
sudo dnf -y module enable php:remi-7.4  && \
sudo dnf config-manager --set-enabled ol8_codeready_builder && \
sudo dnf -y install @php && \
sudo dnf -y install php-{common,opcache,cli,gd,curl,mysqlnd,devel,pear,mbstring,xml} && \
sudo systemctl enable --now php-fpm && \
sudo dnf -y install php-pear && \
sudo pear channel-update pear.php.net && \
sudo pear install DB MDB2 MDB2_Driver_mysqli && \
sudo pear channel-update pear.php.net && \
#freeradius
sudo dnf install -y @freeradius freeradius-utils freeradius-mysql && \
sudo systemctl enable --now radiusd.service && \
#
mysql --user="root" --password="${rootPass}" --execute="CREATE DATABASE ${radNameDB};" && \
mysql --user="root" --password="${rootPass}" --execute="GRANT ALL ON ${radNameDB}.* TO ${radNameDB}@localhost IDENTIFIED BY \"${radPass}\";" && \
mysql --user="root" --password="${rootPass}" --execute="FLUSH PRIVILEGES;" && \
mysql --user="root" --password="${rootPass}" ${radNameDB} < /etc/raddb/mods-config/sql/main/mysql/schema.sql && \
#
sudo ln -s /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/ && \
#
sed -i -E "s/.*dialect[[:space:]]*=[[:space:]]*.*/\
        dialect = \"mysql\"/" /etc/raddb/mods-available/sql && \
#
sed -i -E "1,/.*driver[[:space:]]*=[[:space:]]*.*/{s/.*driver[[:space:]]*=[[:space:]]*.*/\
        driver = \"rlm_sql_mysql\"/;}" /etc/raddb/mods-available/sql && \
#
sed -i -E "1,/.*radius_db[[:space:]]*=[[:space:]]*.*/{s/.*radius_db[[:space:]]*=[[:space:]]*.*/\
        radius_db = \"${radNameDB}\"/;}" /etc/raddb/mods-available/sql && \
#
sed -i -E "1,/.*server[[:space:]]*=[[:space:]]*.*/{s/.*server[[:space:]]*=[[:space:]]*.*/\
        server = \"localhost\"/;}" /etc/raddb/mods-available/sql && \
#
sed -i -E "1,/.*port[[:space:]]*=[[:space:]]*.*/{s/.*port[[:space:]]*=[[:space:]]*.*/\
        port = 3306/;}" /etc/raddb/mods-available/sql && \
#
sed -i -E "1,/.*login[[:space:]]*=[[:space:]]*.*/{s/.*login[[:space:]]*=[[:space:]]*.*/\
        login = \"${radNameDB}\"/;}" /etc/raddb/mods-available/sql && \
#
sed -i "$(grep -n 'password = '  /etc/raddb/mods-available/sql | tail -1 | cut -d: -f1) s/.*/\
        password = \"${radPass}\"/" /etc/raddb/mods-available/sql && \
#
sed -i -E "s/.*read_clients[[:space:]]*=.*/\
        read_clients = yes/" /etc/raddb/mods-available/sql && \
#
sed -i -E "/mysql[[:space:]]\{/,/[[:space:]]\}/{/mysql/,/.*#/! s/./&#/2 }" /etc/raddb/mods-available/sql && \
#
sudo chgrp -h radiusd /etc/raddb/mods-enabled/sql && \
sudo systemctl restart radiusd && \
sudo dnf -y install wget && \
cd /tmp && wget https://github.com/lirantal/daloradius/archive/master.zip && \
sudo dnf -y install unzip && \
unzip master.zip && \
sudo mv daloradius-master/ /var/www/html/daloradius && \
cd /var/www/html/daloradius && \
#
mysql -uroot -p${rootPass} ${radNameDB} < contrib/db/fr2-mysql-daloradius-and-freeradius.sql && \
mysql -uroot -p${rootPass} ${radNameDB} < contrib/db/mysql-daloradius.sql && \
sudo chown -R apache:apache /var/www/html/daloradius/ && \
mv /var/www/html/daloradius/library/daloradius.conf.php.sample /var/www/html/daloradius/library/daloradius.conf.php && \
sudo chmod 664 /var/www/html/daloradius/library/daloradius.conf.php && \
#
sed -i "s/.*\$configValues\['CONFIG_DB_PASS'\].*/\
\$configValues\['CONFIG_DB_PASS'\] = \'${radPass}\'\;/" /var/www/html/daloradius/library/daloradius.conf.php && \
#
sed -i "s/.*\$configValues\['CONFIG_DB_NAME'\].*/\
\$configValues\['CONFIG_DB_NAME'\] = \'${radNameDB}\'\;/" /var/www/html/daloradius/library/daloradius.conf.php && \
#
sed -i "s/.*\$configValues\['CONFIG_DB_USER'\].*/\
\$configValues\['CONFIG_DB_USER'\] = \'${radNameDB}\'\;/" /var/www/html/daloradius/library/daloradius.conf.php && \
#
sudo systemctl restart radiusd.service httpd && \
sudo dnf -y install policycoreutils-python-utils && \
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/daloradius(/.*)?" && \
sudo restorecon -Rv /var/www/html/daloradius && \
sudo systemctl restart radiusd
sed -i -E "s/(.*BY) User (ASC.*)/\1 Username \2/" /var/www/html/daloradius/include/management/fileExport.php
