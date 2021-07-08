#!/bin/bash
#
echo -e \
"=============================================\n\
created by cjijcb • https://github.com/cjijcb\n\
============================================="
#
yum -y install \
libnsl \
perl \
https://pkgs.dyn.su/el8/extras/x86_64/tcp_wrappers-libs-7.6-77.el8.x86_64.rpm \
http://li.nux.ro/download/nux/misc/el7/x86_64/tac_plus-4.0.4.26-1.el7.nux.x86_64.rpm \
http://li.nux.ro/download/nux/misc/el7/x86_64/tac_plus-debuginfo-4.0.4.26-1.el7.nux.x86_64.rpm \
http://li.nux.ro/download/nux/misc/el7/x86_64/tac_plus-devel-4.0.4.26-1.el7.nux.x86_64.rpm && \
service tac_plus start
systemctl enable tac_plus
