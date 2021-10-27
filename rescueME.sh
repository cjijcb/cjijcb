#!/bin/bash
GRN='\033[1;32m'
NC='\033[0m'
BOOL=0
RESCUE_ACCOUNT=eucser
PASSWORD='{f>e,o;I0.tL2T#LGMD<^h'
echo "creating rescue account..."
while [ ${BOOL} -eq 0 ]
do
  if ! sudo useradd -M \
       -G wheel \
       -K PASS_MAX_DAYS=365 \
       -K PASS_WARN_AGE=3 \
       -K LOGIN_RETRIES=3 ${RESCUE_ACCOUNT} > /dev/null 2>&1 && break
  then
     sudo pkill ${RESCUE_ACCOUNT} &&
     sudo userdel ${RESCUE_ACCOUNT}
  fi
done
sudo passwd ${RESCUE_ACCOUNT} <<EOF > /dev/null 2>&1 || exit
${PASSWORD}
${PASSWORD}
EOF
#
echo "disabling root account..."
sudo sed -E -i "s/(^root[^\/]+\/root:).*/\1\/sbin\/nologin/" /etc/passwd &&
sudo sed -E -i "s/^[#]*(PermitRootLogin[[:space:]]+)[[:alpha:]]+/\1no/" /etc/ssh/sshd_config &&
sudo systemctl restart sshd &&
echo -e "${GRN}Success!${NC}"
