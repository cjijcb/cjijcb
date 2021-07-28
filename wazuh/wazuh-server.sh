#!/bin/bash
yum -y  install zip unzip curl tar &&
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch &&
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
#ELASTIC
yum -y install elasticsearch-7.11.2 &&
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.orig &&
curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/elastic-stack/elasticsearch/7.x/elasticsearch_all_in_one.yml &&
curl -so /usr/share/elasticsearch/instances.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/elastic-stack/instances_aio.yml &&
/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip &&
unzip ~/certs.zip -d ~/certs &&
mkdir /etc/elasticsearch/certs/ca -p &&
cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/ &&
chown -R elasticsearch: /etc/elasticsearch/certs &&
chmod -R 500 /etc/elasticsearch/certs &&
chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.* &&
rm -rf ~/certs/ ~/certs.zip &&
#WAZUH
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH &&
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
yum -y install wazuh-manager &&
#FILEBEAT
yum -y install filebeat-7.11.2 &&
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.orig &&
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/elastic-stack/filebeat/7.x/filebeat_all_in_one.yml &&
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json &&
chmod go+r /etc/filebeat/wazuh-template.json &&
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module &&
cp -r /etc/elasticsearch/certs/ca/ /etc/filebeat/certs/ &&
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/filebeat/certs/filebeat.crt &&
cp /etc/elasticsearch/certs/elasticsearch.key /etc/filebeat/certs/filebeat.key &&
#KIBANA
yum -y install kibana-7.11.2 &&
mkdir /etc/kibana/certs/ca -p &&
cp -R /etc/elasticsearch/certs/ca/ /etc/kibana/certs/ &&
cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key &&
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt &&
chown -R kibana:kibana /etc/kibana/ &&
chmod -R 500 /etc/kibana/certs &&
chmod 440 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.* &&
cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.orig &&
curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/elastic-stack/kibana/7.x/kibana_all_in_one.yml &&
mkdir /usr/share/kibana/data &&
chown -R kibana:kibana /usr/share/kibana &&
cd /usr/share/kibana &&
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.1.5_7.11.2-1.zip &&
setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node &&
#
systemctl daemon-reload &&
systemctl enable elasticsearch &&
systemctl start elasticsearch &&
echo 'y' | /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto > genpass &&
elasticpass=$(sed -n -e 's/PASSWORD elastic = //p' ./genpass) &&
sed -i "s/<elasticsearch_password>/$elasticpass/" /etc/filebeat/filebeat.yml &&
sed -i "s/<elasticsearch_password>/$elasticpass/" /etc/kibana/kibana.yml &&
#
sed -i -E "/<auth>/,/<\/auth>/ s/([[:space:]]*<disabled>)[[:alpha:]]+(<\/disabled>)/\1yes\2/" /var/ossec/etc/ossec.conf &&
sed -i -E "/<vulnerability-detector>/,/<provider/ s/([[:space:]]+<enabled>)[[:alpha:]]+(<\/enabled>)/\1yes\2/" /var/ossec/etc/ossec.conf &&
sed -i -E "/<vulnerability-detector>/,/<\/vulnerability-detector>/{/<provider[[:space:]]+name=\"redhat\">/,/<\/provider>/ s/([[:space:]]+<\enabled>)[[:alpha:]]+(<\/enabled>)/\1yes\2/}" /var/ossec/etc/ossec.conf &&
sed -i -E "/<vulnerability-detector>/,/<\/vulnerability-detector>/{/<provider[[:space:]]+name=\"redhat\">/,/<\/provider>/ s/[[:space:]]+(<os>[^8]<\/os>)/ <\!-- \1 -->/}" /var/ossec/etc/ossec.conf &&
sed -i -E "/<vulnerability-detector>/,/<\/vulnerability-detector>/{/<provider[[:space:]]+name=\"redhat\">/,/<\/provider>/ s/([[:space:]]+<os)(>[8]<\/os>)/\1 allow=\"Oracle Linux-8\"\2/}" /var/ossec/etc/ossec.conf &&
sed -i -E "/<syscheck>/,/<\/syscheck>/ s/(<directories)(>.+)/\1 check_all=\"yes\" realtime=\"yes\"\2/" /var/ossec/etc/ossec.conf &&
#
systemctl daemon-reload &&
systemctl enable wazuh-manager &&
systemctl start wazuh-manager &&
#
systemctl daemon-reload &&
systemctl enable filebeat &&
systemctl start filebeat &&
#
systemctl daemon-reload &&
systemctl enable kibana &&
systemctl start kibana
#
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
