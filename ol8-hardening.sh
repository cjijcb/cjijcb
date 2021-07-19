#!/bin/bash
#5000
echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf
#5001
echo 'install vfat /bin/true' >> /etc/modprobe.d/vfat.conf
#5002
echo 'install squashfs /bin/true' >> /etc/modprobe.d/squashfs.conf
#5003
echo 'install udf /bin/true' >> /etc/modprobe.d/udf.conf
#5004
systemctl unmask tmp.mount
systemctl enable tmp.mount
sed -i 's/^Options=.*/Options=mode=1777,strictatime,noexec,nodev,nosuid/' /etc/systemd/system/local-fs.target.wants/tmp.mount
systemctl start tmp.mount
echo 'systemctl start tmp.mount' >> /etc/rc.local
chmod +x /etc/rc.d/rc.local
#5007
echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
mount -o remount,noexec /tmp
echo 'mount -o remount,noexec /tmp' >> /etc/rc.local
chmod +x /etc/rc.d/rc.local
#5019
echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
mount -o remount,noexec /dev/shm
#5021
echo 'install usb-storage /bin/true' >> /etc/modprobe.d/usb-storage.conf
#5025
echo 'Defaults use_pty' >> /etc/sudoers.d/pty
#5026
mkdir /var/log/sudoers
echo 'Defaults logfile=/var/log/sudoers' >>  /etc/sudoers.d/sudoers-log
#5029
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
chown root:root /boot/grub2/grubenv
chmod og-rwx /boot/grub2/grubenv
#5032
sed -i -E "s/[^[:space:]]+([[:space:]]+)[^[:space:]]+([[:space:]]+)core([[:space:]]+)[[:digit:]]+/*\1hard\2core\30/" /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/coredump.conf
#5033
echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/randomize-space.conf
sysctl -w kernel.randomize_va_space=2
#5088
echo 'install tipc /bin/true' >> /etc/modprobe.d/tipc.conf
#5042
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue
#5043
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue.net
#5048
yum -y update --security
#5050
update-crypto-policies --set FIPS
fips-mode-setup --enable
#5075
cho -e \
"net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.send_redirects = 0" \
>> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
#5076
echo -e \
"net.ipv4.conf.all.accept_source_route = 0\n\
net.ipv4.conf.default.accept_source_route = 0\n\
net.ipv6.conf.all.accept_source_route = 0\n\
net.ipv6.conf.default.accept_source_route = 0" \
>> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#5077
echo -e \
"net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0" \
>> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0;
sysctl -w net.ipv6.conf.all.accept_redirects=0;
sysctl -w net.ipv6.conf.default.accept_redirects=0;
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#5078
echo -e \
"net.ipv4.conf.all.secure_redirects = 0\n\
net.ipv4.conf.default.secure_redirects = 0" \
>> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#5078
echo -e \
"net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.default.log_martians = 1" \
>> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#5082
grep -Els "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*0" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.net.ipv4.conf\.all\.rp_filter\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.conf.all.rp_filter=1; sysctl -w net.ipv4.route.flush=1
echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#5084
echo -e \
"net.ipv6.conf.all.accept_ra = 0\n\
net.ipv6.conf.default.accept_ra = 0" \
>> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
#5086
echo 'install sctp /bin/true' >> /etc/modprobe.d/sctp.conf
#5087
echo 'install rds /bin/true' >> /etc/modprobe.d/rds.conf
#5092
systemctl --now mask nftables.service
#5096
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
echo -e \
"ip6tables -P INPUT DROP\n\
ip6tables -P OUTPUT DROP\n\
ip6tables -P FORWARD DROP" \
>> /etc/rc.local
chmod +x /etc/rc.d/rc.local
#5099
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
echo -e \
"iptables -A INPUT -i lo -j ACCEPT\n\
iptables -A OUTPUT -o lo -j ACCEPT\n\
iptables -A INPUT -s 127.0.0.0/8 -j DROP" \
>> /etc/rc.local
#5101
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP
echo -e \
"ip6tables -A INPUT -i lo -j ACCEPT\n\
ip6tables -A OUTPUT -o lo -j ACCEPT\n\
ip6tables -A INPUT -s ::1 -j DROP" \
>> /etc/rc.local
#5102
nmcli radio all off
#5107
grep -q 'GRUB_CMDLINE_LINUX.*audit=1' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(audit=1|.*)\"/\1\2 audit=1"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
#5108
grep -q 'GRUB_CMDLINE_LINUX.*audit_backlog_limit=' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(audit_backlog_limit=|.*)\"/\1\2 audit_backlog_limit=8192"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
#5110
sed -i 's/.*max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
#5111
sed -i 's/.*space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/.*action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf
echo 'admin_space_left_action = halt' >> /etc/audit/auditd.conf
#5114
echo -e \
"-w /var/log/wtmp -p wa -k logins\n\
-w /var/log/btmp -p wa -k logins" \
>> /etc/audit/rules.d/logins.rules
#5116
echo '-w /usr/share/selinux/ -p wa -k MAC-policy' >> /etc/audit/rules.d/MAC-policy.rules
#5117
echo '-w /etc/sysconfig/network-scripts/ -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit_rules_networkconfig_modification.rules
#5118
echo -e \
"-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod\n\
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod\n\
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod\n\
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod\n\
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod\n\
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod" \
>> /etc/audit/rules.d/perm_mod.rules
#5119
echo -e \
"-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access\n\
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access" \
>> /etc/audit/rules.d/access.rules
#5123
echo -e \
"-w /sbin/insmod -p x -k modules\n\
-w /sbin/modprobe -p x -k modules\n\
-w /sbin/rmmod -p x -k modules" \
>> /etc/audit/rules.d/modules.rules
#5124
echo '-w /var/log/sudo.log -p wa -k actions' >> /etc/audit/rules.d/actions.rules
#5127
sed -i '1 i\\$FileCreateMode 0640' /etc/rsyslog.conf
#5129
sed -i -E "s/#*ForwardToSyslog=.*/ForwardToSyslog=yes/" /etc/systemd/journald.conf
#5130
sed -i -E "s/#*Compress=.*/Compress=yes/" /etc/systemd/journald.conf
#5131
sed -i -E "s/#*Storage=.*/Storage=persistent/" /etc/systemd/journald.conf
#5132
find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo 'find /var/log -type f -exec chmod g-wx,o-rwx {} +' >> /etc/rc.local
#5134
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
#5135
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
#5136 !rsyslog
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
#5137
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
#5138
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
#5139
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
#5140
rm -f /etc/cron.deny 
rm -f /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
#5142
echo 'AllowGroups *' >> /etc/ssh/sshd_config
#5143
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
#5146
sed -i -E 's/^#?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
#5147
sed -i -E 's/^#?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
#5154
sed -i 's/.*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
#5155
sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
#5157
sed -i -E 's/^#?AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
#5158
sed -i -E 's/^#?MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
#5161
authselect enable-feature with-faillock
authselect enable-feature without-nullok
#5162
if grep -q "^[[:space:]]*minlen" /etc/security/pwquality.conf
  then sed -i -E "s/(^[[:space:]]*minlen[[:space:]]*=[[:space:]]*)[[:digit:]]+/\18/" /etc/security/pwquality.conf
  else sed -i -E "s/^#+[[:space:]](minlen[[:space:]]*=[[:space:]]*)[[:digit:]]/\18/" /etc/security/pwquality.conf
fi
#5167
sed  -i -E 's/^#?PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
#5169
useradd -D -f 30
#5170
sed -i '1 i readonly TMOUT=900 > /dev/null 2>&1; export TMOUT' /etc/profile
sed -i '1 i readonly TMOUT=900 > /dev/null 2>&1; export TMOUT' /etc/bashrc
#5172
sed -i -E 's/umask[[:space:]]+[[:digit:]]+/umask 027/' /etc/profile.d/*.sh
sed -i -E 's/umask[[:space:]]+[[:digit:]]+/umask 027/' /etc/profile
sed -i -E 's/umask[[:space:]]+[[:digit:]]+/umask 027/' /etc/bashrc
sed -i -E 's/UMASK[[:space:]]+[[:digit:]]+/UMASK\t\t027/' /etc/login.defs
#5173
sed -i -E "s/.*(auth[[:space:]]+required[[:space:]]+pam_wheel.so[[:space:]]+use_uid)/\1/" /etc/pam.d/su
#5178
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
echo -e \
"chown root:root /etc/passwd-\n\
chmod 600 /etc/passwd-" \
>> /etc/rc.local
