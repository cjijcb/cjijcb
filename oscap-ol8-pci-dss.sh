#!/bin/bash
#Set Password Maximum Age
sed -i -E 's/^#?PASS_MAX_DAYS.*/PASS_MAX_DAYS\t60/' /etc/login.defs
#Prevent Login to Accounts With Empty Password
sed -i 's/[[:space:]]nullok[[:space:]]/ /g' /etc/pam.d/system-auth
#Set SSH Client Alive Count Max
sed -i -E 's/#?[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
#Set SSH Idle Timeout Interval
sed -i -E 's/#?[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config
#Ensure Logrotate Runs Periodically
echo 'rotate log files frequency daily' >> /etc/logrotate.conf
#Configure auditd admin_space_left Action on Low Disk Space
sed -i -E 's/#?[[:space:]]*admin_space_left_action.*/admin_space_left_action = SINGLE/' /etc/audit/auditd.conf
#Configure auditd space_left Action on Low Disk Space
sed -i -E 's/\bspace_left_action.*/space_left_action = SINGLE/' /etc/audit/auditd.conf
#Configure auditd to use audispd's syslog plugin
echo "#Configure auditd to use audispd's syslog plugin" >> /etc/audit/rules.d/audit.rules
echo 'active = yes' >> /etc/audit/plugins.d/syslog.conf
#Enabling 
grep -q 'GRUB_CMDLINE_LINUX.*audit=1' /etc/default/grub || sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*)(audit=1|.*)\"/\1\2 audit=1"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
#Record Events that Modify the System's Discretionary Access Controls - chmod
echo "#Record Events that Modify the System's Discretionary Access Controls - chmod" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - setxattr
echo "#Record Events that Modify the System's Discretionary Access Controls - setxattr" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lsetxattr
echo "#Record Events that Modify the System's Discretionary Access Controls - lsetxattr" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lchown
echo "#Record Events that Modify the System's Discretionary Access Controls - lchown" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
echo "#Record Events that Modify the System's Discretionary Access Controls - fremovexattr" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchmoda
echo "#Record Events that Modify the System's Discretionary Access Controls - fchmoda" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lremovexattr
echo "#Record Events that Modify the System's Discretionary Access Controls - lremovexattr" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchmod
echo '-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchownat
echo "#Record Events that Modify the System's Discretionary Access Controls - fchownat" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - chown
echo '-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - removexattr
echo "#Record Events that Modify the System's Discretionary Access Controls - removexattr" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
echo "#Record Events that Modify the System's Discretionary Access Controls - fsetxattr" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchown
echo "#Record Events that Modify the System's Discretionary Access Controls - fchown" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit_module
echo "#Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit_module" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S finit_module -F key=modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S finit_module -F key=modules' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Loading - init_module
echo "#Ensure auditd Collects Information on Kernel Module Loading - init_module" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S init_module -F key=modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S init_module -F key=modules' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Unloading - delete_module
echo "#Ensure auditd Collects Information on Kernel Module Unloading - delete_module" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S delete_module -F key=modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S delete_module -F key=modules' >> /etc/audit/rules.d/audit.rules
#Record Attempts to Alter the localtime File
echo "#Record Attempts to Alter the localtime File" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/localtime -p wa -k audit_time_rules' >> /etc/audit/rules.d/audit.rules
#Record Attempts to Alter Time Through clock_settime
echo "#Record Attempts to Alter Time Through clock_settime" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change' >> /etc/audit/rules.d/audit.rules
#Record attempts to alter time through adjtimex
echo "#Record attempts to alter time through adjtimex" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
#Record attempts to alter time through settimeofday
echo "#Record attempts to alter time through settimeofday" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
#Record attempts to alter time through stime
echo '-a always,exit -F arch=b32 -S stime -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
#Record Attempts to Alter Logon and Logout Events
echo "#Record Attempts to Alter Logon and Logout Events" >> /etc/audit/rules.d/audit.rules
echo '-w /var/log/tallylog -p wa -k logins' >> /etc/audit/rules.d/audit.rules
echo '-w /var/run/faillock -p wa -k logins' >> /etc/audit/rules.d/audit.rules
echo '-w /var/log/lastlog -p wa -k logins' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - rename
echo "#	Ensure auditd Collects File Deletion Events by User - rename" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - unlinkat
echo "#Ensure auditd Collects File Deletion Events by User - unlinkat" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - rmdir
echo "#Ensure auditd Collects File Deletion Events by User - rmdir" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - renameat
echo "#Ensure auditd Collects File Deletion Events by User - renameat" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - unlink
echo "#Ensure auditd Collects File Deletion Events by User - unlink" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - ftruncate
echo "#Record Unsuccessful Access Attempts to Files - ftruncate" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - openat
echo "#Record Unsuccessful Access Attempts to Files - openat" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - truncate
echo "#Record Unsuccessful Access Attempts to Files - truncate" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - open
echo "#Record Unsuccessful Access Attempts to Files - open" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - creat
echo "#Record Unsuccessful Access Attempts to Files - creat" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - open_by_handle_at
echo "#Record Unsuccessful Access Attempts to Files - open_by_handle_at" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
##!Ensure auditd Collects Information on the Use of Privileged Commands
#Record Events that Modify the System's Network Environment
echo "#Record Events that Modify the System's Network Environment" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/issue -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/hosts -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/issue -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/hosts -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/gshadow
echo "#Record Events that Modify User/Group Information - /etc/gshadow" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/gshadow -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects System Administrator Actions
echo "#Ensure auditd Collects System Administrator Actions" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/sudoers -p wa -k actions' >> /etc/audit/rules.d/audit.rules
echo '-w /etc/sudoers.d/ -p wa -k actions' >> /etc/audit/rules.d/audit.rules
#Record Attempts to Alter Process and Session Initiation Information
echo "#Record Attempts to Alter Process and Session Initiation Information" >> /etc/audit/rules.d/audit.rules
echo '-w /var/run/utmp -p wa -k session' >> /etc/audit/rules.d/audit.rules
echo '-w /var/log/btmp -p wa -k session' >> /etc/audit/rules.d/audit.rules
echo '-w /var/log/wtmp -p wa -k session' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Exporting to Media (successful)
echo "#Ensure auditd Collects Information on Exporting to Media (successful)" >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=export' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=export' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/passwd
echo "#Record Events that Modify User/Group Information - /etc/passwd" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/passwd -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/shadow
echo "#Record Events that Modify User/Group Information - /etc/shadow" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/shadow -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/group
echo "#Record Events that Modify User/Group Information - /etc/group" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/group -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Mandatory Access Controls
echo "#Record Events that Modify the System's Mandatory Access Controls" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/selinux/ -p wa -k MAC-policy' >> /etc/audit/rules.d/audit.rules
#Make the auditd Configuration Immutable
echo "#Make the auditd Configuration Immutable" >> /etc/audit/rules.d/99-finalize.rules
echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules
#Record Events that Modify User/Group Information - /etc/security/opasswd
echo "#Record Events that Modify User/Group Information - /etc/security/opasswd" >> /etc/audit/rules.d/audit.rules
echo '-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Install audispd-plugins Package
yum -y install audispd-plugins
#Set Account Expiration Following Inactivity
sed -i 's/^INACTIVE.*/INACTIVE=60/' /etc/default/useradd
#Set Password Maximum
sed -iE 's/#?PASS_MAX_DAYS.*/PASS_MAX_DAYS\t180/' /etc/login.defs
##!Force opensc To Use Defined Smart Card Driver
##!Configure opensc Smart Card Drivers
#Install the pcsc-lite package
yum -y install pcsc-lite
#Enable the pcscd Service
systemctl enable pcscd.service
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
##!	Ensure PAM Displays Last Logon/Access Notification
echo '05 4 * * * root /usr/sbin/aide --check' >> /etc/crontab
#Install AIDE
yum -y install aide
#install libreswan package
yum -y install libreswan
#
sudo service auditd restart
#Ensure auditd Collects Information on the Use of Privileged Commands
echo "#Ensure auditd Collects Information on the Use of Privileged Commands" >> /etc/audit/rules.d/audit.rules
for PROG_PATH in $( find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null )
do
  echo "-a always,exit -F path=$PROG_PATH -F auid>=1000 -F auid!=unset -F key=privileged" >> /etc/audit/rules.d/audit.rules
done

