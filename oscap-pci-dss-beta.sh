#!/bin/bash
append() {
  arr=("$@")
  file=${arr[-1]}
  unset 'arr[${#arr[@]}-1]'
  for i in "${arr[@]}"; do
    echo "$i" >> "$file"
  done
}
#Set Password Maximum Age @5166
sed -i -E 's/^#?PASS_MAX_DAYS.*/PASS_MAX_DAYS\t60/' /etc/login.defs
#Prevent Login to Accounts With Empty Password
sed -i 's/[[:space:]]nullok[[:space:]]/ /g' /etc/pam.d/system-auth
#Set SSH Client Alive Count Max
sed -i -E 's/#?[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
#Set SSH Idle Timeout Interval
sed -i -E 's/#?[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config
#Ensure Logrotate Runs Periodically
sed -i -E 's/^[[:space:]]*(weekly|monthly|yearly)/daily/' /etc/logrotate.conf
#Configure auditd admin_space_left Action on Low Disk Space
sed -i -E 's/#?[[:space:]]*admin_space_left_action.*/admin_space_left_action = SINGLE/' /etc/audit/auditd.conf
#Configure auditd space_left Action on Low Disk Space
sed -i -E 's/\bspace_left_action.*/space_left_action = EMAIL/' /etc/audit/auditd.conf
#Configure auditd to use audispd's syslog plugin
append \
"#Configure auditd to use audispd's syslog plugin" \
'active = yes' \
/etc/audit/plugins.d/syslog.conf
#Enabling 
grep -q 'GRUB_CMDLINE_LINUX.*audit=1' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(audit=1|.*)\"/\1\2 audit=1"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
#Record Events that Modify the System's Discretionary Access Controls - chmod
append \
"#Record Events that Modify the System's Discretionary Access Controls - chmod" \
'-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - setxattr
append \
"#Record Events that Modify the System's Discretionary Access Controls - setxattr" \
'-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lsetxattr
append \
"#Record Events that Modify the System's Discretionary Access Controls - lsetxattr" \
'-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lchown
append \
"#Record Events that Modify the System's Discretionary Access Controls - lchown" \
'-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
append \
"#Record Events that Modify the System's Discretionary Access Controls - fremovexattr" \
'-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchmoda
append \
"#Record Events that Modify the System's Discretionary Access Controls - fchmoda" \
'-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lremovexattr
append \
"#Record Events that Modify the System's Discretionary Access Controls - lremovexattr" \
'-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchmod
append \
'-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchownat
append \
"#Record Events that Modify the System's Discretionary Access Controls - fchownat" \
'-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - chown
append \
'-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - removexattr
append \
"#Record Events that Modify the System's Discretionary Access Controls - removexattr" \
'-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
append \
"#Record Events that Modify the System's Discretionary Access Controls - fsetxattr" \
'-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchown
append \
"#Record Events that Modify the System's Discretionary Access Controls - fchown" \
'-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod' \
'-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit_module
append \
"#Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit_module" \
'-a always,exit -F arch=b32 -S finit_module -F key=modules' \
'-a always,exit -F arch=b64 -S finit_module -F key=modules' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Loading - init_module
append \
"#Ensure auditd Collects Information on Kernel Module Loading - init_module" \
'-a always,exit -F arch=b32 -S init_module -F key=modules' \
'-a always,exit -F arch=b64 -S init_module -F key=modules' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Unloading - delete_module
append \
"#Ensure auditd Collects Information on Kernel Module Unloading - delete_module" \
'-a always,exit -F arch=b32 -S delete_module -F key=modules' \
'-a always,exit -F arch=b64 -S delete_module -F key=modules' \
/etc/audit/rules.d/audit.rules
#Record Attempts to Alter the localtime File
append \
"#Record Attempts to Alter the localtime File" \
'-w /etc/localtime -p wa -k audit_time_rules' \
/etc/audit/rules.d/audit.rules
#Record Attempts to Alter Time Through clock_settime
append \
"#Record Attempts to Alter Time Through clock_settime" \
'-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change' \
'-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change' \
/etc/audit/rules.d/audit.rules
#Record attempts to alter time through adjtimex
append \
"#Record attempts to alter time through adjtimex" \
'-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules' \
'-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules' \
/etc/audit/rules.d/audit.rules
#Record attempts to alter time through settimeofday
append \
"#Record attempts to alter time through settimeofday" \
'-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules' \
'-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules' \
/etc/audit/rules.d/audit.rules
#Record attempts to alter time through stime
append \
'-a always,exit -F arch=b32 -S stime -F key=audit_time_rules' \
/etc/audit/rules.d/audit.rules
#Record Attempts to Alter Logon and Logout Events
append \
"#Record Attempts to Alter Logon and Logout Events" \
'-w /var/log/tallylog -p wa -k logins' \
'-w /var/run/faillock -p wa -k logins' \
'-w /var/log/lastlog -p wa -k logins' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - rename
append \
"#Ensure auditd Collects File Deletion Events by User - rename" \
'-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete' \
'-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - unlinkat
append \
"#Ensure auditd Collects File Deletion Events by User - unlinkat" \
'-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete' \
'-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - rmdir
append \
"#Ensure auditd Collects File Deletion Events by User - rmdir" \
'-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete' \
'-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - renameat
append \
"#Ensure auditd Collects File Deletion Events by User - renameat" \
'-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete' \
'-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - unlink
append \
"#Ensure auditd Collects File Deletion Events by User - unlink" \
'-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete' \
'-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete' \
/etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - ftruncate
append \
"#Record Unsuccessful Access Attempts to Files - ftruncate" \
'-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
/etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - openat
append \
"#Record Unsuccessful Access Attempts to Files - openat" \
'-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
/etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - truncate
append \
"#Record Unsuccessful Access Attempts to Files - truncate" \
'-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
/etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - open
append \
"#Record Unsuccessful Access Attempts to Files - open" \
'-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
/etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - creat
append \
"#Record Unsuccessful Access Attempts to Files - creat" \
'-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
/etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - open_by_handle_at
append \
"#Record Unsuccessful Access Attempts to Files - open_by_handle_at" \
'-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' \
'-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' \
/etc/audit/rules.d/audit.rules
##!Ensure auditd Collects Information on the Use of Privileged Commands
#Record Events that Modify the System's Network Environment
append \
"#Record Events that Modify the System's Network Environment" \
'-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification' \
'-w /etc/issue -p wa -k audit_rules_networkconfig_modification' \
'-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification' \
'-w /etc/hosts -p wa -k audit_rules_networkconfig_modification' \
'-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification' \
'-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification' \
'-w /etc/issue -p wa -k audit_rules_networkconfig_modification' \
'-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification' \
'-w /etc/hosts -p wa -k audit_rules_networkconfig_modification' \
'-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/gshadow
append \
"#Record Events that Modify User/Group Information - /etc/gshadow" \
'-w /etc/gshadow -p wa -k audit_rules_usergroup_modification' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects System Administrator Actions
append \
"#Ensure auditd Collects System Administrator Actions" \
'-w /etc/sudoers -p wa -k actions' \
'-w /etc/sudoers.d/ -p wa -k actions' \
/etc/audit/rules.d/audit.rules
#Record Attempts to Alter Process and Session Initiation Information
append \
"#Record Attempts to Alter Process and Session Initiation Information" \
'-w /var/run/utmp -p wa -k session' \
'-w /var/log/btmp -p wa -k session' \
'-w /var/log/wtmp -p wa -k session' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Exporting to Media (successful)
append \
"#Ensure auditd Collects Information on Exporting to Media (successful)" \
'-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=export' \
'-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=export' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/passwd
append \
"#Record Events that Modify User/Group Information - /etc/passwd" \
'-w /etc/passwd -p wa -k audit_rules_usergroup_modification' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/shadow
append \
"#Record Events that Modify User/Group Information - /etc/shadow" \
'-w /etc/shadow -p wa -k audit_rules_usergroup_modification' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/group
append \
"#Record Events that Modify User/Group Information - /etc/group" \
'-w /etc/group -p wa -k audit_rules_usergroup_modification' \
/etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Mandatory Access Controls
append \
"#Record Events that Modify the System's Mandatory Access Controls" \
'-w /etc/selinux/ -p wa -k MAC-policy' \
/etc/audit/rules.d/audit.rules
#Make the auditd Configuration Immutable
append \
"#Make the auditd Configuration Immutable" \
'-e 2' \
/etc/audit/rules.d/99-finalize.rules
#Record Events that Modify User/Group Information - /etc/security/opasswd
append \
"#Record Events that Modify User/Group Information - /etc/security/opasswd" \
'-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification' \
/etc/audit/rules.d/audit.rules
#Install audispd-plugins Package
yum -y install audispd-plugins
#Set Account Expiration Following Inactivity
sed -i 's/^INACTIVE.*/INACTIVE=60/' /etc/default/useradd
#Install the pcsc-lite package
yum -y install pcsc-lite
#Enable the pcscd Service
systemctl enable pcscd.service
systemctl start pcscd.service
#sudo yum install opensc
yum -y install opensc
#Ensure PAM Enforces Password Requirements - Minimum Digit Characters
sed -i -E 's/#?[[:space:]]*dcredit.*/dcredit = -1/'  /etc/security/pwquality.conf
#Ensure PAM Enforces Password Requirements - Minimum Lowercase Characters
sed -i -E 's/#?[[:space:]]*lcredit.*/lcredit = -1/'  /etc/security/pwquality.conf
#Ensure PAM Enforces Password Requirements - Minimum Length
sed -i -E 's/#?[[:space:]]*minlen.*/minlen = 8/'  /etc/security/pwquality.conf
#Ensure PAM Enforces Password Requirements - Minimum Uppercase Characters
sed -i -E 's/#?[[:space:]]*ucredit.*/ucredit = -1/'  /etc/security/pwquality.conf
##!Set Lockout Time for Failed Password Attempts && ##!Set Deny For Failed Password Attempts
sed -i "$(grep -n '^auth.*pam_unix.so' /etc/pam.d/system-auth  | cut -f1 -d:) i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800 fail_interval=900" /etc/pam.d/system-auth
sed -i "$(grep -n '^auth.*pam_unix.so' /etc/pam.d/system-auth  | cut -f1 -d:) a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800 fail_interval=900" /etc/pam.d/system-auth
sed -i "$(grep -n '^account.*pam_unix.so' /etc/pam.d/system-auth  | cut -f1 -d:) i account required pam_faillock.so" /etc/pam.d/system-auth
sed -i "$(grep -n '^auth.*pam_unix.so' /etc/pam.d/password-auth  | cut -f1 -d:) i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800 fail_interval=900" /etc/pam.d/password-auth
sed -i "$(grep -n '^auth.*pam_unix.so' /etc/pam.d/password-auth  | cut -f1 -d:) a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800 fail_interval=900" /etc/pam.d/password-auth
sed -i "$(grep -n '^account.*pam_unix.so' /etc/pam.d/password-auth  | cut -f1 -d:) i account required pam_faillock.so" /etc/pam.d/password-auth
#Limit Password Reuse	
grep -q 'password.*requisite.*pam_pwquality.*so.*remember=' /etc/pam.d/system-auth || sed -i -E 's/^(password.*requisite.*pam_pwquality.*so.)(.*)(remember=|.*)/\1\2 remember=5/' /etc/pam.d/system-auth
grep -q 'password.*sufficient.*pam_unix.*so.*remember=' /etc/pam.d/system-auth || sed -i -E 's/^(password.*sufficient.*pam_unix.*so.)(.*)(remember=|.*)/\1\2 remember=5/' /etc/pam.d/system-auth
#Install AIDE
yum -y install aide
#install libreswan package
yum -y install libreswan
##!	Ensure PAM Displays Last Logon/Access Notification
echo '05 4 * * * root /usr/sbin/aide --check' >> /etc/crontab
#
sudo service auditd restart
#Ensure auditd Collects Information on the Use of Privileged Commands
append \
"#Ensure auditd Collects Information on the Use of Privileged Commands" \
/etc/audit/rules.d/audit.rules
for PROG_PATH in $( find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null )
do
  echo "-a always,exit -F path=$PROG_PATH -F auid>=1000 -F auid!=unset -F key=privileged" >> /etc/audit/rules.d/audit.rules
done
#Verify and  Correct File Permission with RPM
#for FILE in $( rpm -Va | awk '{ if (substr($0,2,1)=="M") print $NF }' )
#do
#  PKG=$( rpm -qf $FILE )
#  rpm --setperms $PKG
#done
#Ensure PAM Displays Last Logon/Access Notification
sed -i "s/session[[:space:]]*\[default=1\][[:space:]]*pam_lastlog.so[[:space:]]*nowtmp[[:space:]].*/\
session\
     [default=1]\
     pam_lastlog.so nowtmp showfailed/" /etc/pam.d/postlogin
#Force opensc To Use Defined Smart Card Driver
opensc-tool -S app:default:force_card_driver:cac
#Configure opensc Smart Card Drivers
opensc-tool -S app:default:card_drivers:cac
#Specify Additional Remote NTP Server
var_multiple_time_servers="0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org"

config_file="/etc/ntp.conf"
/usr/sbin/pidof ntpd || config_file="/etc/chrony.conf"

if ! [ "$(grep -c '^server' "$config_file")" -gt 1 ] ; then
  if ! grep -q '#[[:space:]]*server' "$config_file" ; then
    for server in $(echo "$var_multiple_time_servers" | tr ',' '\n') ; do
      printf '\nserver %s' "$server" >> "$config_file"
    done
  else
    sed -i 's/#[ \t]*server/server/g' "$config_file"
  fi
fi
#Ensure auditd Collects Informartion on the Use of Privileged Commmands - sudoedit
append \
'#Ensure auditd Collects Informartion on the Use of Privileged Commmands - sudoedit' \
'-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=unset -F key=privileged' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Informartion on the Use of Privileged Commmands - pstdrop
append \
  '#Ensure auditd Collects Informartion on the Use of Privileged Commmands - pstdrop' \
  '-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -F key=privileged' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Informartion on the Use of Privileged Commmands - usernetctl
append \
'#Ensure auditd Collects Informartion on the Use of Privileged Commmands - usernetctl' \
'-a always,exit -F path=/usr/sbin/usernetctl -F auid>=1000 -F auid!=unset -F key=privileged' \
/etc/audit/rules.d/audit.rules
#Ensure auditd Collects Informartion on the Use of Privileged Commmands - postqueue
append \
'#Ensure auditd Collects Informartion on the Use of Privileged Commmands - postqueue' \
'-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -F key=privileged' \
/etc/audit/rules.d/audit.rules
#Disable At Service (atd)
systemctl mask --now atd.service
#Ensure No World-Writable File Exist
find / -xdev -type f -perm -002 -exec chmod o-w {} \;
#Build and Test AIDE
if ! rpm -q --quiet "aide" ; then
  yum install -y "aide"
fi
/usr/sbin/aide --init
/bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
