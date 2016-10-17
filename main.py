# -*- coding: utf-8 -*-
"""
Created on Wed Oct 12 22:45:54 2016

@author: skipi

get CVE database from Cisco API Oauth2 

"""

import requests
import json
from pprint import pprint
import get_token
import get_csas
import yaml

print 'Parsing configs ...'
with open("config.yaml", 'r') as yamlfile:
    cfg = yaml.load(yamlfile)

for section in cfg:
    clientId = cfg['CiscoCreds']['clientId']
    clientSecret = cfg['CiscoCreds']['clientSecret']
print 'done ...'

#clientID = 'zetgk3mrfy58nwvbe239tqtr'
#clientSecret = 'JkSydPCAnS28M82dKXG94RfY'

ciscoToken = get_token.get_token(clientId, clientSecret)

#print clientId
#print clientSecret

print 'Getting CSAs ...'
get_csas.get_csas(ciscoToken,'LATEST','5')
print 'done getting CSAs ...'        