#!/bin/bash
RD='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m'
#
echo -n -e "Enter the IPA ${GRN}Server Name${NC}:"
read IPA_SRVR
if [[ -z "$IPA_SRVR" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
echo -n -e "Enter the IPA ${GRN}Server IP${NC}:"
read IPA_IP
if [[ -z "$IPA_IP" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
echo -n -e "Enter the IPA ${GRN}Admin password${NC}:"
read IPA_ADMIN_PASS
if [[ -z "$IPA_IP" ]];
  then echo -e "${RD}Error${NC}: you entered nothing."; exit 1;
fi
#
sed -i -E "/${IPA_IP}[[:space:]]+${IPA_SRVR}/d" /etc/hosts
echo "${IPA_IP} ${IPA_SRVR}" >> /etc/hosts && \
#
chattr -i /etc/resolv.conf
sed -i -E "/nameserver[[:space:]]+${IPA_IP}/d" /etc/resolv.conf
sed -i "$( grep -n nameserver /etc/resolv.conf | head -1 | cut -d: -f1 ) i nameserver ${IPA_IP}" /etc/resolv.conf && \
chattr +i /etc/resolv.conf
#
IPA_DMN=$( sed -E -n "s/[^\.]+\.(.*)/\1/p" <<< $IPA_SRVR )
#
yum -y module enable idm:DL1 && \
yum -y install ipa-client\* && \
ipa-client-install \
--force-join \
--mkhomedir \
--server=${IPA_SRVR} \
--domain=${IPA_DMN} \
--principal=admin \
--password=${IPA_ADMIN_PASS} <<EOF || exit
yes
no
yes
EOF
