#!/bin/bash
sed -i.bak -E 's/^(GRUB_CMDLINE_LINUX)(.*) (intel_iommu=on|.*)\"/\1\2 intel_iommu=on"/' /etc/default/grub &&
grub2-mkconfig -o /boot/grub2/grub.cfg &&
echo 'rebooting this machine is required. Would you like to reboot now?[y/n]' &&
read YN
YN=$(echo $YN | tr '[:upper:]' '[:lower:]')
case $YN in
    y) reboot ;;
    yes) reboot ;;
    n)  exit 0;;
    no) exit 0;;
    *)  exit 0;;
esac
