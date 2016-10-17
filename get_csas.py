# -*- coding: utf-8 -*-
"""
Created on Wed Oct 12 22:45:54 2016

@author: skipi

get CVE database from Cisco API

"""

import requests
import json
import urllib
import datetime
import wget
import get_cves

def get_csas(ciscoToken,csaParam,csaParamValue):
    """
    get_csas
    
    ciscoToken - auth token from Cisco API Oauth
    csaParam - search by what
    csaParamValue - search parameter value
    
    """

    date = str(datetime.date.today())

    ciscoTokenHeader = "Bearer " + ciscoToken

    csaBaseUrl = 'https://api.cisco.com/security'

    csaUrlY = '/advisories/cvrf/year/' # <YYYY - year>
    csaUrlAll = '/advisories/cvrf/all'
    csaUrlCve = '/advisories/cvrf/cve/' # <CVEID>
    csaUrlAdv = '/advisories/cvrf/advisory/' # <advisoryId>
    csaUrlSev = '/advisories/cvrf/severity/' # <critical|high|medium|low>
    csaUrlLatest = '/advisories/cvrf/latest/' # <number of latest csas>

    if csaParam == 'YEAR':
       csaUrl = csaBaseUrl + csaUrlY + csaParamValue
    elif csaParam == 'ALL':
       csaUrl = csaBaseUrl + csaUrlAll + csaParamValue
    elif csaParam == 'CVE':
       csaUrl = csaBaseUrl + csaUrlCve + csaParamValue
    elif csaParam == 'ADVIS':
       csaUrl = csaBaseUrl + csaUrlAdv + csaParamValue
    elif csaParam == 'SEV':
       csaUrl = csaBaseUrl + csaUrlSev + csaParamValue
    elif csaParam == 'LATEST':
       csaUrl = csaBaseUrl + csaUrlLatest + csaParamValue

#    csaUrl = csaBaseUrl + csaUrlLatest + csaParamValue

    print 'Getting CSA JSON ...'
    csaHeaders = {'Accept': 'application/json', 'Authorization': ciscoTokenHeader}

    csaResponse = requests.get(csaUrl, headers = csaHeaders)

    print 'Writting CSA CSV file ...'
    if (csaResponse.ok):
        csaContent = json.loads(csaResponse.content)

        csvFile = open("./REPORTS/" + date + ".csv",'wb')
        
#        print "sir;cvrfUrl;lastUpdated;firstPublished;advisoryId;CVE list"     
        csvFile.write("sir;cvrfUrl;lastUpdated;firstPublished;advisoryId;CVE list")
        

        
        for line in csaContent["advisories"]:
            print 'Getting CSA XML description file for ' + line ['advisoryId']
#            csaFile = wget.download(csaUrl)            
            csaFile = open("./CSAs/" + line["advisoryId"] + ".xml",'wb')
            csaFile.write(requests.get(line["cvrfUrl"]).content)
            csaFile.close()
                    
            cve_list = ""
            for cve in line["cves"]:
                print 'ToDo: Download description for ' + cve + ' ...'
                print get_cves.get.cve(cve)
                if cve_list == "":
                    cve_list = cve
                else:
                    cve_list = cve_list + ", " + cve
        
            report = line["sir"] + ";" + line["advisoryId"] + ";" + line["lastUpdated"] + ";" + line["firstPublished"] + ";" + cve_list + ";" + line["cvrfUrl"]


#            print report        
            csvFile.write("\n" + report)
            
        csvFile.close()
            
#	FUNKCNY download CSA files - NEMAZAT !!!

#            csaFile = open("./CSAs/" + line["advisoryId"] + ".xml",'wb')
#            csaFile.write(requests.get(line["cvrfUrl"]).content)
#            csaFile.close()
            
#get_csas('xxxxxxxxxxxx')
