#!/bin/bash
#Prevent Login to Accounts With Empty Password
sed -i 's/[[:space:]]nullok[[:space:]]/ /g' /etc/pam.d/system-auth
#Set SSH Client Alive Count Max
sed -iE 's/#?[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
#Set SSH Idle Timeout Interval
sed -iE 's/#?[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config
#Ensure Logrotate Runs Periodically
echo 'rotate log files frequency daily' >> /etc/logrotate.conf
#Configure auditd admin_space_left Action on Low Disk Space
sed -iE 's/#?[[:space:]]*admin_space_left_action.*/admin_space_left_action = ACTION/' /etc/audit/auditd.conf
#Configure auditd space_left Action on Low Disk Space
sed -iE 's/\bspace_left_action.*/space_left_action = ACTION/' /etc/audit/auditd.conf
#Configure auditd to use audispd's syslog plugin	
echo 'active = yes' >> /etc/audit/plugins.d/syslog.conf
sudo service auditd restart
#Record Events that Modify the System's Discretionary Access Controls - chmod
echo '-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
sudo service auditd restart
#Record Events that Modify the System's Discretionary Access Controls - setxattr
echo '-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
sudo service auditd restart
#Record Events that Modify the System's Discretionary Access Controls - lsetxattr
echo '-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
sudo service auditd restart
#Record Events that Modify the System's Discretionary Access Controls - lchown
echo '-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
echo '-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchmoda
echo '-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - lremovexattr
echo '-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchownat
echo '-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - removexattr
echo '-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
echo '-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Discretionary Access Controls - fchown
echo '-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit_module
echo '-a always,exit -F arch=b32 -S finit_module -F key=modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S finit_module -F key=modules' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Loading - init_module
echo '-a always,exit -F arch=b32 -S init_module -F key=modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S init_module -F key=modules' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Kernel Module Unloading - delete_module
echo '-a always,exit -F arch=b32 -S delete_module -F key=modules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S delete_module -F key=modules' >> /etc/audit/rules.d/audit.rules
#Record Attempts to Alter the localtime File
echo '-w /etc/localtime -p wa -k audit_time_rules >> /etc/audit/rules.d/audit.rules'
#Record Attempts to Alter Time Through clock_settime
echo '-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change' >> /etc/audit/rules.d/audit.rules
#Record attempts to alter time through adjtimex
echo '-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
#Record attempts to alter time through settimeofday
echo '-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules' >> /etc/audit/rules.d/audit.rules
#Record Attempts to Alter Logon and Logout Events
echo '-w /var/log/tallylog -p wa -k logins -w /var/run/faillock -p wa -k logins -w /var/log/lastlog -p wa -k logins' >> /etc/audit/rules.d/audit.rules
#	Ensure auditd Collects File Deletion Events by User - rename
echo '-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - unlinkat
echo '-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - rmdir
echo '-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects File Deletion Events by User - renameat
echo '-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#	Ensure auditd Collects File Deletion Events by User - unlink
echo '-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - ftruncate
echo '-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S ftruncate -F exiu=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - openat
echo '-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - truncate
echo '-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - open
echo '-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - creat
echo '-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access >> /etc/audit/rules.d/audit.rules' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access >> /etc/audit/rules.d/audit.rules' >> /etc/audit/rules.d/audit.rules
#Record Unsuccessful Access Attempts to Files - open_by_handle_at
echo '-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' >> /etc/audit/rules.d/audit.rules
##!Ensure auditd Collects Information on the Use of Privileged Commands
#Record Events that Modify the System's Network Environment
echo '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification -w /etc/issue -p wa -k audit_rules_networkconfig_modification -w /etc/issue.net -p wa -k audit_rules_networkconfig_modification -w /etc/hosts -p wa -k audit_rules_networkconfig_modification -w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification -w /etc/issue -p wa -k audit_rules_networkconfig_modification -w /etc/issue.net -p wa -k audit_rules_networkconfig_modification -w /etc/hosts -p wa -k audit_rules_networkconfig_modification -w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/gshadow
echo '-w /etc/gshadow -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects System Administrator Actions
echo '-w /etc/sudoers -p wa -k actions -w /etc/sudoers.d/ -p wa -k actions' >> /etc/audit/rules.d/audit.rules
#	Record Attempts to Alter Process and Session Initiation Information
echo '-w /var/run/utmp -p wa -k session -w /var/log/btmp -p wa -k session -w /var/log/wtmp -p wa -k session' >> /etc/audit/rules.d/audit.rules
#Ensure auditd Collects Information on Exporting to Media (successful)
echo '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=export' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=export' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/passwd
echo '-w /etc/passwd -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify User/Group Information - /etc/group
echo '-w /etc/group -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Record Events that Modify the System's Mandatory Access Controls
echo '-w /etc/selinux/ -p wa -k MAC-policy' >> /etc/audit/rules.d/audit.rules
#Make the auditd Configuration Immutable
echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules
#Record Events that Modify User/Group Information - /etc/security/opasswd
echo '-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification' >> /etc/audit/rules.d/audit.rules
#Install audispd-plugins Package
yum -y install audispd-plugins
#Set Account Expiration Following Inactivity
sed -i 's/^INACTIVE.*/INACTIVE=60/' /etc/default/useradd
#Set Password Maximum
sed -iE 's/#?PASS_MAX_DAYS.*/PASS_MAX_DAYS\t180/' /etc/login.defs
##!Force opensc To Use Defined Smart Card Driver
##!Configure opensc Smart Card Drivers
#Enable the pcscd Service
systemctl enable pcscd.service
#Install the pcsc-lite package
yum -y install pcsc-lite
#sudo yum install opensc
yum -y install opensc
#Ensure PAM Enforces Password Requirements - Minimum Digit Characters
sed -iE 's/#?[[:space:]]*dcredit.*/dcredit = 1/'  /etc/security/pwquality.conf
#Ensure PAM Enforces Password Requirements - Minimum Lowercase Characters
sed -iE 's/#?[[:space:]]*lcredit.*/lcredit = 1/'  /etc/security/pwquality.conf
#Ensure PAM Enforces Password Requirements - Minimum Length
 sed -E 's/#?[[:space:]]*minlen.*/minlen = 8/'  /etc/security/pwquality.conf
#Ensure PAM Enforces Password Requirements - Minimum Uppercase Characters
sed -E 's/#?[[:space:]]*ucredit.*/ucredit = 1/'  /etc/security/pwquality.conf
##!Set Lockout Time for Failed Password Attempts
##!Set Deny For Failed Password Attempts
##!Limit Password Reuse	
##!	Ensure PAM Displays Last Logon/Access Notification
echo '05 4 * * * root /usr/sbin/aide --check' >> /etc/crontab
#Install AIDE
yum -y install aide
