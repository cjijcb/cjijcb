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

