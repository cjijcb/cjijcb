#!/bin/bash
RD='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m'
IPV4=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4[[:space:]](.*)\/.*/\1/p}" ) >/dev/null 2>&1
#
echo -e "Enter a new password for ${GRN}Directory Manager${NC}:"
read DM_PASS
if [[ -z "$DM_PASS" ]] || [[ $(wc -m <<< "$DM_PASS") -lt 9 ]];
  then echo -e "${RD}Error:${NC} password cannot be empty and should be alteast 8 characters long."; exit 1;
fi
#
echo -e "Enter a new for password ${GRN}IPA admin${NC}:"
read IPA_PASS
if [[ -z "$IPA_PASS" ]] || [[ $(wc -m <<< "$IPA_PASS") -lt 9 ]];
  then echo -e "${RD}Error:${NC} password cannot be empty and should be alteast 8 characters long."; exit 1;
fi
#
if ! grep -q -E "${IPV4}[[:space:]]+$(hostname)" /etc/hosts && [[ -n "${IPV4}" ]];
  then echo "${IPV4} $(hostname)" >> /etc/hosts
fi
#
yum -y module enable idm:DL1
yum -y install ipa\*
#
ipa-server-install --mkhomedir <<EOF
yes
$DEFAULT
$DEFAULT
$DEFAULT
${DM_PASS}
${DM_PASS}
${IPA_PASS}
${IPA_PASS}
yes
no
208.67.222.222
208.67.220.220
$DEFAULT
yes
yes
$DEFAULT
no
yes
EOF
#
kinit admin <<EOF
${IPA_PASS}
EOF
