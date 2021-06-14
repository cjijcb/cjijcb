#!/bin/bash

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
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
#Record Events that Modify the System's Discretionary Access Controls - removexattr
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
#Record Events that Modify the System's Discretionary Access Controls - fchown
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
#Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit_module
-a always,exit -F arch=b32 -S finit_module -F key=modules
-a always,exit -F arch=b64 -S finit_module -F key=modules
#Ensure auditd Collects Information on Kernel Module Loading - init_module
-a always,exit -F arch=b32 -S init_module -F key=modules
-a always,exit -F arch=b64 -S init_module -F key=modules
#Ensure auditd Collects Information on Kernel Module Unloading - delete_module
-a always,exit -F arch=b32 -S delete_module -F key=modules
-a always,exit -F arch=b64 -S delete_module -F key=modules
#Record Attempts to Alter the localtime File
-w /etc/localtime -p wa -k audit_time_rules
#Record Attempts to Alter Time Through clock_settime
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
#Record attempts to alter time through adjtimex
-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
#Record attempts to alter time through settimeofday
-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
#Record Attempts to Alter Logon and Logout Events
-w /var/log/tallylog -p wa -k logins -w /var/run/faillock -p wa -k logins -w /var/log/lastlog -p wa -k logins
#	Ensure auditd Collects File Deletion Events by User - rename
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
#Ensure auditd Collects File Deletion Events by User - unlinkat
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
#Ensure auditd Collects File Deletion Events by User - rmdir
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
#Ensure auditd Collects File Deletion Events by User - renameat
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
#	Ensure auditd Collects File Deletion Events by User - unlink
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
#Record Unsuccessful Access Attempts to Files - ftruncate
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exiu=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
#Record Unsuccessful Access Attempts to Files - openat
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
#Record Unsuccessful Access Attempts to Files - truncate
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
#Record Unsuccessful Access Attempts to Files - open
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
#Record Unsuccessful Access Attempts to Files - creat
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
#Record Unsuccessful Access Attempts to Files - open_by_handle_at
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access







