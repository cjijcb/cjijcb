#!/bin/bash
yum -y module enable virt
yum -y install qemu-kvm libvirt-client\* libvirt-daemon\* xorg-x11-xauth virt-install virt-manager virt-clone
systemctl enable --now libvirtd
systemctl restart libvirtd
sed -i.bak -E "s/^[[:space:]]*(GRUB_CMDLINE_LINUX=.+)intel_iommu=[^[:space:]]+[[:space:]](.*)/\1\2/" /etc/default/grub && \
sed -i -E "s/^[[:space:]]*(GRUB_CMDLINE_LINUX=.+)[[:space:]]intel_iommu=[^(\"|\')]+/\1/" /etc/default/grub && \
sed -i -E "s/^[[:space:]]*(GRUB_CMDLINE_LINUX=)[[:space:]]*(.)(.*)(\"|\')/\1\2\3 intel_iommu=on\2/" /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
