#!/bin/bash
yum -y enable virt
yum -y install qemu-kvm libvirt-client\* libvirt-daemon\* xorg-x11-xauth virt-install virt-manager virt-clone
systemctl enable --now libvirtd
systemctl restart libvirtd
sed -i -E 's/^(GRUB_CMDLINE_LINUX)(.*) (intel_iommu=on|.*)\"/\1\2 intel_iommu=on"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
