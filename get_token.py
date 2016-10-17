# -*- coding: utf-8 -*-
"""
Created on Wed Oct 12 22:45:54 2016

@author: skipi

get auth token from Cisco API Oauth2 

"""

import requests
import json
from pprint import pprint

clientID = 'zetgk3mrfy58nwvbe239tqtr'
clientSecret = 'JkSydPCAnS28M82dKXG94RfY'

def get_token(client_id, client_secret):

    tokenURL = 'https://cloudsso.cisco.com/as/token.oauth2'
    tokenHeaders = {'Content-Type': 'application/x-www-form-urlencoded'}
    tokenData = {'client_id': clientID, 'client_secret': clientSecret, 'grant_type': 'client_credentials'}

    tokenResponse = requests.post(tokenURL, params=tokenData, headers = tokenHeaders)

    if (tokenResponse.ok):

    # Loading the response data into a dict variable
    # json.loads takes in only binary or string variables so using content to fetch binary content
    # Loads (Load String) takes a Json file and converts into python data structure (dict or list, depending on JSON)
        tokenData = json.loads(tokenResponse.content)

#        print(tokenData["access_token"])
        return(tokenData["access_token"])
