#!/bin/bash
yum -y install mod_ssl
mkdir -p /etc/httpd/ssl/private
chmod 700 /etc/httpd/ssl/private
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/httpd/ssl/private/apache-selfsigned.key -out /etc/httpd/ssl/apache-selfsigned.crt <<EOF
${NULL}
${NULL}
${NULL}
${NULL}
${NULL}
$(hostname)
${NULL}
EOF
sed -i \
"s/^DocumentRoot.*/DocumentRoot \"\/usr\/share\/zabbix\"/; \
s/^ServerName.*/ServerName 127.0.0.1:443/; \
s/^SSLCertificateFile.*/SSLCertificateFile \/etc\/httpd\/ssl\/apache-selfsigned.crt/; \
s/^SSLCertificateKeyFile.*/SSLCertificateKeyFile \/etc\/httpd\/ssl\/private\/apache-selfsigned.key/" \
/etc/httpd/conf.d/ssl.conf
systemctl restart httpd
