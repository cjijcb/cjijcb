#!/bin/bash
sed -i '/%ASA/ s/^[^:]/:&/' /var/log/cisco-asa.log /var/log/cisco-ios.log /var/log/messages #
sed -i -E '/%[A-Z]+.*-[0-9]-[A-Z]+/ s/^[^:]/:&/' /var/log/cisco-asa.log /var/log/cisco-ios.log /var/log/messages #

