#!/bin/bash
echo -n "Enter the Wazuh server IP:" 
read WAZUH_SERVER_IP
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
#
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
#
WAZUH_MANAGER="${WAZUH_SERVER_IP}" yum -y install wazuh-agent
sed -i -E "/<syscheck>/,/<\/syscheck>/ s/(<directories)(>.+)/\1 check_all=\"yes\" realtime=\"yes\"\2/" /var/ossec/etc/ossec.conf
cp /var/ossec/ruleset/sca/cis_rhel8_linux.yml{.,bak0}
curl -s https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/cis_rhel8_linux.yml > /var/ossec/ruleset/sca/cis_rhel8_linux.yml
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
