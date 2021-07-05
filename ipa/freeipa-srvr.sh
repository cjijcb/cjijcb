#!/bin/bash
RD='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m'
IPV4=$( nmcli | sed -E -n "/: connected to/,/inet4/{/inet4/ s/.*inet4[[:space:]](.*)\/.*/\1/p}" ) >/dev/null 2>&1
#
echo -e "Enter a new password for ${GRN}Directory Manager${NC}:"
read DM_PASS
if [[ -z "$DM_PASS" ]] || [[ $(wc -m <<< "$DM_PASS") -lt 9 ]];
  then echo -e "${RD}Error${NC}: password cannot be empty and should be alteast 8 characters long."; exit 1;
fi
#
echo -e "Enter a new for password ${GRN}IPA admin${NC}:"
read IPA_PASS
if [[ -z "$IPA_PASS" ]] || [[ $(wc -m <<< "$IPA_PASS") -lt 9 ]];
  then echo -e "${RD}Error${NC}: password cannot be empty and should be alteast 8 characters long."; exit 1;
fi
#
if ! grep -q -E "${IPV4}[[:space:]]+$(hostname)" /etc/hosts && [[ -n "${IPV4}" ]];
  then echo "${IPV4} $(hostname)" >> /etc/hosts
fi
#
yum -y module enable idm:DL1
yum -y install ipa\*
#
ipa-server-install \
--admin-password=${IPA_PASS} \
--ds-password=${DM_PASS} \
--setup-dns \
--setup-adtrust \
--setup-kra \
--auto-reverse \
--forwarder=208.67.222.222 \
--forwarder=208.67.220.220 \
--mkhomedir \
--enable-compat \
--no-ntp <<EOF
${DEFAULT}
${DEFAULT}
${DEFAULT}
${DEFAULT}
yes
EOF
#
kinit admin <<EOF
${IPA_PASS}
EOF
#
ipa config-mod --defaultshell=/bin/bash
#
ipa sudorule-add superusers --hostcat=all --cmdcat=all --runasusercat=all --runasgroupcat=all
mv /usr/share/ipa/ui/images/header-logo.png /usr/share/ipa/ui/images/header-logo.png.bak
mv /usr/share/ipa/ui/images/product-name.png /usr/share/ipa/ui/images/product-name.png.bak
mv /usr/share/ipa/ui/images/login-screen-logo.png /usr/share/ipa/ui/images/login-screen-logo.png.bak
curl -s -o /usr/share/ipa/ui/images/header-logo.png https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/header-logo.png
curl -s -o /usr/share/ipa/ui/images/product-name.png https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/product-name.png
curl -s -o /usr/share/ipa/ui/images/login-screen-logo.png https://raw.githubusercontent.com/cjijcb/cjijcb/main/sources/login-screen-logo.png
