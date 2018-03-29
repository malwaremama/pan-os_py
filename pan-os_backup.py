#!/usr/bin/env python
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET
import time
import datetime

#fwhost can be either an IP address or a DNS record - enter it below between the quotation marks
#for an IP address, it would look like: fwhost = "192.168.1.1"
#for a DNS object, it would look like: fwhost = "fwmanagement.yourdomain.com"
fwhost = ""

#fwkey is the API key that is generated by the firewall for the account that the API will impersonate
#You can generate the key using the following URL to the firewall:
#https://<firewall>/api?type=keygen&user=<username>&password=<password>
#The response will be in XML and the key will be between the <key> and </key> tags
#Copy that entire key into the variable below between the quotation marks
fwkey = ""

#Make call to firewall to get the configuration XML
values = {'type': 'op', 'cmd': '<show><config><running></running></config></show>', 'key': fwkey}
palocall = 'https://%s/api/' % (fwhost)
config = requests.post(palocall, data=values, verify=False)

#Use the timestamp to create a unique filename
filename = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + '.xml'

#Write the config backup to a file
fwfile = open(filename, 'w')
fwfile.write(config.text)
fwfile.close()