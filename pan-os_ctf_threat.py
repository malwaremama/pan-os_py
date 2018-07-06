#!/usr/bin/env python
DOCUMENTATION = '''
---
short_description: this script will load the Palo Alto Networks threat prevention security best practices to the PA-VMs.
description: this script was written for use at the 2018 BSides LV in the Pros vs. Joes CTF. This script will update the PA-VMs that are a part of the cyber range to follow security best practices as well as detect L4-L7 evasion techniques. This is relevant for PAN-OS 8.0.X versioning.
author: @malwaremama with a big frickin' slice of @p0lr_
version: 1.0 - initial release WAHOO!
         1.1 - fixed commit jobs status reporting
requirements:
    - this was written in Python3.6.
    - you will need Python and Requests installed.
    - you will need to have the blueteam_secrets.py in the same directory as this script.
        [blueteam_secrets.py should contain the proper keys and host information in order to make the API calls to the PA-VMs]
JUST_SEND_IT:
    - change access permissions 'chmod 755' of this file and run the script.
'''

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET
import blueteam_secrets

# Input to define which credentials to use
teamName = input("Which Blue Team firewall would you like to modify? [alpha/gamma/delta/epsilon]: ")
if teamName == 'alpha':
    fwHost = blueteam_secrets.alphaFWhost
    apiKey = blueteam_secrets.alphaAPIkey
elif teamName == 'delta':
    fwHost = blueteam_secrets.deltaFWhost
    apiKey = blueteam_secrets.deltaAPIkey
elif teamName == 'gamma':
    fwHost = blueteam_secrets.gammaFWhost
    apiKey = blueteam_secrets.gammaAPIkey
elif teamName == 'epsilon':
    fwHost = blueteam_secrets.epsilonFWhost
    apiKey = blueteam_secrets.epsilonAPIkey
else:
    print("You done messed up, A-Aron...!")

def updateSecurityProfile(fwHost, apiKey, cmd, teamName):

    values = {'type': 'op', 'cmd': cmd, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(r.text)
    print("Applying security magic..." + tree.get('status'))

cmd_list = []
# Zone Protection Profile
cmd_list.append("<load><config><partial><mode>merge</mode><from>{team}-golden-tp-config</from><from-xpath>/config/devices/entry[@name='localhost.localdomain']/network/profiles/zone-protection-profile</from-xpath><to-xpath>/config/devices/entry[@name='localhost.localdomain']/network/profiles/zone-protection-profile</to-xpath></partial></config></load>".format(team=teamName))

# Threat Prevention Security Profiles & Group
cmd_list.append("<load><config><partial><mode>merge</mode><from>{team}-golden-tp-config</from><from-xpath>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles</from-xpath><to-xpath>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles</to-xpath></partial></config></load>".format(team=teamName))
cmd_list.append("<load><config><partial><mode>merge</mode><from>{team}-golden-tp-config</from><from-xpath>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profile-group</from-xpath><to-xpath>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profile-group</to-xpath></partial></config></load>".format(team=teamName))

# Apply Best Practices Security Profile Group to Allow-All Rule
cmd_list.append("<load><config><partial><mode>merge</mode><from>{team}-golden-tp-config</from><from-xpath>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase</from-xpath><to-xpath>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase</to-xpath></partial></config></load>".format(team=teamName))

# Apply Device > Setup > Content-ID L4-L7 Evasion Settings
cmd_list.append("<load><config><partial><mode>merge</mode><from>{team}-golden-tp-config</from><from-xpath>/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/ctd</from-xpath><to-xpath>/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/ctd</to-xpath></partial></config></load>".format(team=teamName))

# Update WildFire Every 15-minutes
cmd_list.append("<load><config><partial><mode>merge</mode><from>{team}-golden-tp-config</from><from-xpath>/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/wildfire</from-xpath><to-xpath>/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/wildfire</to-xpath></partial></config></load>".format(team=teamName))

for cmd in cmd_list:

    updateSecurityProfile(fwHost, apiKey, cmd, teamName)

# Update Blue Team Admin Role to ctf-threat-admin

xpath =  "/config/mgt-config/users/entry[@name='{team}-admin']/permissions/role-based/custom".format(team=teamName)
element = "<profile>ctf-threat-admin</profile>"
values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
palocall = 'https://{host}/api/'.format(host=fwHost)
r = requests.post(palocall, data=values, verify=False)
tree = ET.fromstring(r.text)
print ("Updating {team}-admin administrator role".format(team=teamName) + '-' + tree.get('status'))

# Commit and Monitor Commit Job for Completion
print ("*****************************************************************************")
commit = input("Would you like to commit these changes? [y/n]: ")
if commit == "y" or commit == "Y":

    values = {'type': 'commit', 'cmd': '<commit><force></force></commit>', 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(r.text)
    jobID = tree[0][1].text
    print ("Commit job - " + str(jobID))

    committed = 0
    while (committed == 0):
        cmd = "<show><jobs><id>{jobid}</id></jobs></show>".format(jobid=jobID)
        values = {'type': 'op', 'cmd': cmd, 'key': apiKey}
        palocall = 'https://{host}/api/'.format(host=fwHost)
        r = requests.post(palocall, data=values, verify=False)
        tree = ET.fromstring(r.text)
        if (tree[0][0][5].text == 'FIN'):
            print ("Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete")
            committed = 1

        else:
           status = "Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
           print ("{0}\r".format(status)),
else:
    print ("The changes have been made to the candidate configuration, but have not been committed.")
