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






