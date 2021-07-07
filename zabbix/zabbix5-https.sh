#!/bin/bash
GRN='\033[1;32m'
NC='\033[0m'
IPV4=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4[[:space:]](.*)\/.*/\1/p}" ) && \
yum -y install mod_ssl && \
mkdir -p /etc/httpd/ssl/private && \
chmod 700 /etc/httpd/ssl/private && \
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/httpd/ssl/private/apache-selfsigned.key -out /etc/httpd/ssl/apache-selfsigned.crt > /dev/null 2>&1 <<EOF || exit
${NULL}
${NULL}
${NULL}
${NULL}
${NULL}
$(hostname)
${NULL}
EOF
echo "Configuring SSL Certificate..."
sed -i \
"s/^[#]*[[:space:]]*DocumentRoot.*/DocumentRoot \"\/usr\/share\/zabbix\"/; \
s/^[#]*[[:space:]]*ServerName.*/ServerName ${IPV4}:443/; \
s/^[#]*[[:space:]]*SSLCertificateFile.*/SSLCertificateFile \/etc\/httpd\/ssl\/apache-selfsigned.crt/; \
s/^[#]*[[:space:]]*SSLCertificateKeyFile.*/SSLCertificateKeyFile \/etc\/httpd\/ssl\/private\/apache-selfsigned.key/" \
/etc/httpd/conf.d/ssl.conf && \
systemctl restart httpd && \
echo -e "${GRN}HTTPS successfully enabled.${NC}"
