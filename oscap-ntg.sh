#!/bin/bash
yum -y install python3
PY_PATH=$( whereis 'python3' | sed -E 's/.*[[:space:]](\/.+python3)[^.].*/\1/' )
ln -s $PY_PATH /usr/bin/python 2> /dev/null
yum -y install openscap openscap-utils scap-security-guide
mkdir -p /var/ossec/wodles/oscap/content
cp /usr/share/xml/scap/ssg/content/*ds.xml /var/ossec/wodles/oscap/content/
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/oscap > /var/ossec/wodles/oscap/oscap
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/oscap.py > /var/ossec/wodles/oscap/oscap.py
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/template_xccdf.xsl > /var/ossec/wodles/oscap/template_xccdf.xsl
curl https://raw.githubusercontent.com/cjijcb/cjijcb/main/template_oval.xsl > /var/ossec/wodles/oscap/template_oval.xsl
OSC_PATH='/var/ossec/etc/ossec.conf'
sed -i '/<.*wodle.+open-scap/,/<\/.*wodle.*>/ d' $OSC_PATH
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
  <\/wodle>\n" $OSC_PATH
sed -i '/^$/N;/^\n$/D' $OSC_PATH
