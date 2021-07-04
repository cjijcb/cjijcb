#!/bin/bash
yum -y enable virt
yum -y install qemu-kvm libvirt-client\* libvirt-daemon\* xorg-x11-xauth virt-install virt-manager virt-clone
systemctl enable --now libvirtd
systemctl restart libvirtd
if ! grep -q -E "GRUB_CMDLINE_LINE=.*intel_iommu=on" /etc/default/grub; then
sed -i -E "s/^[[:space:]]*(GRUB_CMDLINE_LINUX=)[[:space:]]*(.)(.*)[[:space:]]+(intel_iommu=on|.*)(\"|\')/\1\2\3 intel_iommu=on\2/" /etc/default/grub
fi
grub2-mkconfig -o /boot/grub2/grub.cfg
