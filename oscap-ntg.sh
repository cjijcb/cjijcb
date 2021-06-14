#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
echo 'Installing python3'
  yum -qy install python3 && \
     echo -e "${GREEN}[SUCCESS]${NC}"   
PY_PATH=$( whereis 'python3' | sed -E 's/.*[[:space:]](\/.+python3)[^.].*/\1/' )
ln -s $PY_PATH /usr/bin/python 2> /dev/null
echo 'Installing OpenScap'
  yum -qy install openscap openscap-utils scap-security-guide && \
      echo -e "${GREEN}[SUCCESS]${NC}"
mkdir -p /var/ossec/wodles/oscap/content
cp /usr/share/xml/scap/ssg/content/*ds.xml /var/ossec/wodles/oscap/content/
echo 'Downloading OpenScap shell script'
  curl -s https://raw.githubusercontent.com/cjijcb/cjijcb/main/oscap > /var/ossec/wodles/oscap/oscap && \
    echo -e "${GREEN}[SUCCESS]${NC}"
echo 'Downloading OpenScap python script'
  curl -s https://raw.githubusercontent.com/cjijcb/cjijcb/main/oscap.py > /var/ossec/wodles/oscap/oscap.py && \
    echo -e "${GREEN}[SUCCESS]${NC}"
echo 'Downloading xccdf template'
  curl -s https://raw.githubusercontent.com/cjijcb/cjijcb/main/template_xccdf.xsl > /var/ossec/wodles/oscap/template_xccdf.xsl && \
    echo -e "${GREEN}[SUCCESS]${NC}"
echo 'Downloading oval template'
  curl -s https://raw.githubusercontent.com/cjijcb/cjijcb/main/template_oval.xsl > /var/ossec/wodles/oscap/template_oval.xsl && \
    echo -e "${GREEN}[SUCCESS]${NC}"
OSC_PATH='/var/ossec/etc/ossec.conf'
echo 'Configuring Ossec'
sed -iE '/<.*wodle.\+open-scap/,/<\/.*wodle.*>/ d' $OSC_PATH
WDL=$( grep -n --color=never '<.*/.*wodle.*>' $OSC_PATH | tail -1  | cut -f1 -d: )
sed -i "$WDL G; $WDL a\\
  <wodle name=\"open-scap\">\n\
    <disabled>no<\/disabled>\n\
    <timeout>1800<\/timeout>\n\
    <interval>12h<\/interval>\n\
    <scan-on-start>yes</scan-on-start>\n\
\n\
    <content type=\"xccdf\" path=\"ssg-ol8-ds.xml\">\n\
      <profile>xccdf_org.ssgproject.content_profile_pci-dss<\/profile>\n\
    <\/content>\n\
  <\/wodle>\n" $OSC_PATH && \
echo -e "${GREEN}[SUCCESS]${NC}"
sed -i '/^$/N;/^\n$/D' $OSC_PATH
chmod +x /var/ossec/wodles/oscap/oscap
chmod +x /var/ossec/wodles/oscap/oscap.py
rpm -q wazuh-agent && echo 'agent.remote_conf=0' >> /var/ossec/etc/local_internal_options.conf
/var/ossec/bin/ossec-control restart
