#!/bin/bash
#
touch /var/log/cisco-asa.log
touch /var/log/cisco-ios.log
touch /var/log/cisco-vlan.log
touch /var/log/pfsense.log
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/syslogrotate > /etc/logrotate.d/syslogrotate
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/pfsense-syslog.conf > /etc/rsyslog.d/pfsense-syslog.conf
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/cisco-vlan-syslog.conf > /etc/rsyslog.d/cisco-vlan-syslog.conf
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/cisco-asa-syslog.conf > /etc/rsyslog.d/cisco-asa-syslog.conf
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/cisco-ios-syslog.conf > /etc/rsyslog.d/cisco-ios-syslog.conf
#
systemctl restart rsyslog
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/cisco-asa-syslog.sh > /etc/systemd/system/cisco-asa-syslog.sh
chmod +x /etc/systemd/system/cisco-asa-syslog.sh
#
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/cisco-asa-syslog.service > /etc/systemd/system/cisco-asa-syslog.service
systemctl daemon-reload
systemctl enable --now cisco-asa-syslog.service
systemctl start cisco-asa-syslog.service
#
mv /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/ossec.conf > /var/ossec/etc/ossec.conf
#
mv /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml.bak
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/local_decoder.xml > /var/ossec/etc/decoders/local_decoder.xml
#
mv /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/local_rules.xml > /var/ossec/etc/rules/local_rules.xml
#
mv /var/ossec/ruleset/decoders/0064-cisco-asa_decoders.xml /var/ossec/ruleset/decoders/0064-cisco-asa_decoders.xml.bak
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/0064-cisco-asa_decoders.xml > /var/ossec/ruleset/decoders/0064-cisco-asa_decoders.xml
#
mv /var/ossec/ruleset/decoders/0065-cisco-ios_decoders.xml /var/ossec/ruleset/decoders/0065-cisco-ios_decoders.xml.bak
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/wazuh.config-tangent/0065-cisco-ios_decoders.xml > /var/ossec/ruleset/decoders/0065-cisco-ios_decoders.xml
#
