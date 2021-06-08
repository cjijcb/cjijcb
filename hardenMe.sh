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
#5132
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
#5178
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
update-crypto-policies --set FUTURE
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
#




















 







