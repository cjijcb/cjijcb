#!/bin/bash
#5000
echo 'install cramfs /bin/true' >> /etc/modprobe.d/hardening.conf &&
#5001
echo 'install vfat /bin/true' >> /etc/modprobe.d/hardening.conf &&
#5002
echo 'install squashfs /bin/true' >>  /etc/modprobe.d/hardening.conf &&
#5003 
echo 'install udf /bin/true' >> /etc/modprobe.d/hardening.conf &&
#5025
echo 'Defaults use_pty' >>  /etc/sudoers &&
#5026
mkdir /var/log/sudoers &&
echo 'Defaults logfile=/var/log/sudoers' >>  /etc/sudoers &&
#5029
chown root:root /boot/grub2/grub.cfg &&
chmod og-rwx /boot/grub2/grub.cfg &&
chown root:root /boot/grub2/grubenv &&
chmod og-rwx /boot/grub2/grubenv &&
#5107
grep -q 'GRUB_CMDLINE_LINUX.*audit=1' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(audit=1|.*)\"/\1\2 audit=1"/' /etc/default/grub &&
grub2-mkconfig -o /boot/grub2/grub.cfg &&
#5125
echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules &&
#5130
echo 'Compress=yes' >> /etc/systemd/journald.conf &&
#5131
echo 'Storage=persistent' >>/etc/systemd/journald.conf &&
#5132 !reboot 
find /var/log -type f -exec chmod g-wx,o-rwx {} +
#5143
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \; 
#5154
sed -i 's/.*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config &&
#5155
sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config &&
#5166
sed -i 's/.*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs &&
#5167
sed -i 's/.*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs &&
#5169
useradd -D -f 30 &&
#5173
echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su &&
#5178 !reboot
chown root:root /etc/passwd- &&
chmod 600 /etc/passwd- &&
#5108
grep -q 'GRUB_CMDLINE_LINUX.*audit_backlog_limit=' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(audit_backlog_limit=|.*)\"/\1\2 audit_backlog_limit=8192"/' /etc/default/grub &&
grub2-mkconfig -o /boot/grub2/grub.cfg &&
#5110
sed -i 's/.*max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
#5111
sed -i 's/.*space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/.*action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf
echo 'admin_space_left_action = halt' >> /etc/audit/auditd.conf
#5042
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue
#5043
echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue.net
#5033
echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2
#5032
echo '* hard core 0' >> /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
sed -i 's/.*Storage=.*/Storage=none/' /etc/systemd/coredump.conf
sed -i 's/.*ProcessSizeMax.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf 
systemctl daemon-reload
#5050
update-crypto-policies --set FIPS
#5097
systemctl --now enable nftables
#5075
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
#5082
grep -Els "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*0" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.net.ipv4.conf\.all\.rp_filter\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.conf.all.rp_filter=1; sysctl -w net.ipv4.route.flush=1
echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#5078
echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#5084
echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.accept_ra = 0' >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
#5140
rm -f /etc/cron.deny 
rm -f /etc/at.deny
touch /etc/cron.allo
touch /etc/at.allow
chmod og-rwx
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
#5076
echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.accept_source_route = 0' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.accept_source_route = 0' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#5142
echo 'AllowUsers root' >> /etc/ssh/sshd_config
#5129
echo 'ForwardToSyslog=yes' >>  /etc/systemd/journald.conf
#5112
echo '-w /etc/sudoers -p wa -k scope -w /etc/sudoers.d/ -p wa -k scope'  >> /etc/audit/rules.d/audit.rules
#5113
echo '-w /var/log/lastlog -p wa -k logins -w /var/run/faillock/ -p wa -k logins'  >> /etc/audit/rules.d/audit.rules
#5114
echo '-w /var/run/utmp -p wa -k session -w /var/log/wtmp -p wa -k logins -w /var/log/btmp -p wa -k logins'  >> /etc/audit/rules.d/audit.rules
#5116
echo '-w /etc/selinux/ -p wa -k MAC-policy -w /usr/share/selinux/ -p wa -k MAC-policy'  >> /etc/audit/rules.d/audit.rules
#5117
echo '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale -w /etc/issue -p wa -k system-locale -w /etc/issue.net -p wa -k system-locale -w /etc/hosts -p wa -k system-locale -w /etc/sysconfig/network -p wa -k system-locale -w /etc/sysconfig/network-scripts/ -p wa -k system-locale'  >> /etc/audit/rules.d/audit.rules
#5124
echo '-w /var/log/sudo.log -p wa -k actions' >>  /etc/audit/rules.d/audit.rules
#5127
sed -i '1 i\\$FileCreateMode 0640' /etc/rsyslog.conf
#5170
sed -i '1 i/readonly TMOUT=900 ; export TMOUT' /etc/profile
sed -i '1 i readonly TMOUT=900 ; export TMOUT' /etc/bashrc
#5102
nmcli radio all off
#5103
grep -q 'GRUB_CMDLINE_LINUX.*ipv6.disable=' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(ipv6.disable=1|.*)\"/\1\2 ipv6.disable=1"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
#5115
echo '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S clock_settime -k time-change' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -k time-change' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S clock_settime -k time-change' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/localtime -p wa -k time-change' >> /etc/audit/rules.d/audit.rules
#5118
echo '#cis_5118' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
#5120
echo '#cis_5120' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/group -p wa -k identity' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/gshadow -p wa -k identity' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/security/opasswd -p wa -k identity' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/audit.rules
#5121
echo '#cis_5121' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' >> /etc/audit/rules.d/audit.rules
#5052
yum -y install chrony
#5119
echo '#cis_5119' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules
#5122
echo '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' >> /etc/audit/rules.d/audit.rules
#5123
echo '#cis_5123' >> /etc/audit/rules.d/audit.rules
echo '-w /sbin/insmod -p x -k modules' >> /etc/audit/rules.d/audit.rules
echo '-w /sbin/modprobe -p x -k modules' >> /etc/audit/rules.d/audit.rules
echo '-w /sbin/rmmod -p x -k modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' >> /etc/audit/rules.d/audit.rules
#5027
yum -y install aide
#5093 !reboot
iptables -F
ip6tables -F
#5164
grep -q 'password.*requisite.*pam_pwquality.*so.*remember=' /etc/pam.d/system-auth || sed -i -E 's/^(password.*requisite.*pam_pwquality.*so.)(.*)(remember=|.*)/\1\2 remember=5/' /etc/pam.d/system-auth
grep -q 'password.*sufficient.*pam_unix.*so.*remember=' /etc/pam.d/system-auth || sed -i -E 's/^(password.*sufficient.*pam_unix.*so.)(.*)(remember=|.*)/\1\2 remember=5/' /etc/pam.d/system-auth
#5163
sed -i "$(grep -n '^auth' /etc/pam.d/system-auth | tail -1 | cut -f1 -d:) a auth\trequired\tpam_faillock.so deny=5 unlock_time=900" /etc/pam.d/system-auth
sed -i "$(grep -n '^auth' /etc/pam.d/password-auth | tail -1 | cut -f1 -d:) a auth\trequired\tpam_faillock.so deny=5 unlock_time=900" /etc/pam.d/password-auth
#5162
echo 'minlen = 14' >> /etc/security/pwquality.conf
#5077
grep -E -q 'net.ipv4.conf.all.accept_redirects[[:space:]]*=[[:space:]]*' /etc/sysctl.conf || echo 'net.ipv4.conf.all.accept_redirects=0' >> /etc/sysctl.conf
grep -E -q 'net.ipv4.conf.default.accept_redirects[[:space:]]*=[[:space:]]*' /etc/sysctl.conf || echo 'net.ipv4.conf.default.accept_redirects=0' >> /etc/sysctl.conf
grep -E -q 'net.ipv6.conf.all.accept_redirects[[:space:]]*=[[:space:]]*' /etc/sysctl.conf || echo 'net.ipv6.conf.all.accept_redirects=0' >> /etc/sysctl.conf
grep -E -q 'net.ipv6.conf.default.accept_redirects[[:space:]]*=[[:space:]]*' /etc/sysctl.conf || echo 'net.ipv6.conf.default.accept_redirects=0' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0;
sysctl -w net.ipv6.conf.all.accept_redirects=0;
sysctl -w net.ipv6.conf.default.accept_redirects=0;
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#

















 







