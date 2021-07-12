#!/bin/bash
GRN='\033[1;32m'
NC='\033[0m'
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
#
echo "[1/6] stoping firewalld..."
systemctl stop firewalld > /dev/null 2>&1 && \
echo "[2/6] disabling firewalld..."
systemctl disable firewalld > /dev/null 2>&1 && \
echo "[3/6] masking firewalld..."
systemctl mask firewalld > /dev/null 2>&1 && \
echo "[4/6] installing iptables..."
yum -y install iptables-services > /dev/null 2>&1 && \
echo "[4/6] configuring iptables..."
cat > /etc/sysconfig/iptables <<EOF || exit
# sample configuration for iptables service
# you can edit this manually or use system-config-firewall
# please do not ask us to add additional ports/services to this default configuration
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
#-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
#-A INPUT -p icmp -j ACCEPT
#-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT

# Kaspersky
-A INPUT -p tcp -m state --state NEW -m tcp --dport 13000 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport 13000 -j ACCEPT

#TACACS
-A INPUT -p tcp -m state --state NEW -m tcp --dport 49 -j ACCEPT

#FREEIPA
-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 636 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 389 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 88 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 464 -j ACCEPT

-A INPUT -p udp -m state --state NEW -m udp --dport 389 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport 88 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport 464 -j ACCEPT

#DNS SERVER
-A INPUT -p tcp -m state --state NEW -m tcp --dport 53 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport 53 -j ACCEPT

#ZABBIX
-A INPUT -p tcp -m state --state NEW -m tcp --dport 10050 -j ACCEPT
-A OUTPUT -p tcp -m state --state NEW -m tcp --dport 10050 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 10051 -j ACCEPT
-A OUTPUT -p tcp -m state --state NEW -m tcp --dport 10051 -j ACCEPT

#FREERADIUS
-A INPUT -p tcp -m state --state NEW -m tcp --dport 1812 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport 1812 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 1813 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport 1813 -j ACCEPT

#NTP
-A OUTPUT -p udp -m state --state NEW -m udp --dport 123 -j ACCEPT

#SQUID
-A INPUT -p tcp -m state --state NEW -m tcp --dport 3128 -j ACCEPT

#A INPUT -j REJECT --reject-with icmp-host-prohibited
#A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
#
echo "[5/6] enabling iptables..."
systemctl enable iptables > /dev/null 2>&1 && \
echo "[6/6] starting iptables..."
systemctl restart iptables > /dev/null 2>&1 && \
echo -e "${GRN}iptables successfully installed and configured.${NC}"
