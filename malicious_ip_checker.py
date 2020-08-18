#!/usr/local/python3

import pdb
import json
import socket
import requests
import os
import subprocess
from ipwhois import IPWhois
from colorama import Fore,Back,Style,init
init()

reporturl="https://api.abuseipdb.com/api/v2/report"

class MaliciousIPCheck():

        def __init__(self):
            pass
        
        def resolving_ip(self,url_ip):
            ipaddr=socket.gethostbyname(url_ip)
            return ipaddr
            
        def whois_info(self,url_ip): #Abuse Contact from WHOIs
                op=IPWhois(url_ip)
                whoisinfo=op.lookup_whois()
                final=json.dumps(whoisinfo,indent=4)
                with open ("/var/tmp/whoisinfo.json","w") as file:
                        file.write(final)

        def virus_total(self,url_ip): #VirusTotal
                apiurl="https://www.virustotal.com/api/v3/ip_addresses/"+url_ip
                header={
                "Accept":"application/json",
                "x-apikey":"d7d6a11ef42197bb2195d14fe6039160969dfbf6320e2a86f715835b8a5770b7"
                }
                r=requests.request(method='GET',url=apiurl,headers=header)
                decodedresponse=json.loads(r.text)
                final=json.dumps(decodedresponse,sort_keys=True,indent=4)
                with open ("/var/tmp/vt-info.json","w") as file:
                        file.write(final)

        def abuse_ipdb(self,url_ip): #AbuseIPDB
                url='https://api.abuseipdb.com/api/v2/check'
                reporturl="https://api.abuseipdb.com/api/v2/report"
                qs={
                        'ipAddress':url_ip,
                        'maxAgeInDays':'90'
                }
                report={
                        'ip':url_ip,
                        'categories':'18,19',
                        #'comment':'Malicious Attempts'
                }
                header={
                        'Accept':'application/json',
                        'Key':'f0735fbab3a67a0abd24497c0171309bb87a82521f45922f19c985c189c5e4341607ff533f3c1da6'
                }
                response=requests.request(method='GET',url=url,headers=header,params=qs)
                decodedresponse=json.loads(response.text)
                output=json.dumps(decodedresponse,sort_keys=True,indent=4)
                with open('/var/tmp/abuseaddresses.json','w') as file:
                        file.write(output)

        def report_abipdb(self,url_ip):
                report={
                        'ip':url_ip,
                        'categories':'18,19',
                        #'comment':'Malicious Attempts'
                }
                header={
                        'Accept':'application/json',
                        'Key':'--This is just an example, please register for your own API Key--'
                }
                reportedresponse=requests.request(method='POST',url=reporturl,headers=header,params=report)
                drafterreport=json.loads(reportedresponse.text)
                reportedoutput=json.dumps(drafterreport,sort_keys=True,indent=4)
                with open('/var/tmp/represponse.json','w') as myfile:
                    myfile.write(reportedoutput)
