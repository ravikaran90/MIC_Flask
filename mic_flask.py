#!/usr/bin/python3

import os
import json
import secrets
from flask import Flask, request, render_template, session
from malicious_ip_checker import MaliciousIPCheck

mic=Flask(__name__)
temp=secrets.token_urlsafe(16)
mic.config["SECRET_KEY"]="temp"

@mic.route("/reported")
def reported():
    reportedobj=MaliciousIPCheck()
    ip_addr=session.get("IPADDR")
    reportedobj.report_abipdb(ip_addr)
    with open('/var/tmp/abuseaddresses.json') as f3:
        abipdb=json.load(f3)
        abconfscore=abipdb['data']['abuseConfidenceScore']
    return '''
        <html>
            <body>
                <title>Reported</title>
                <h1 style="color:green;font-size:18px;">The IP address has been reported.</h1>
                <h1 style="color:red;font-size:18px;">Abuse Confidence Score:{abconfscore}</h1>
            </body>
        </html>
'''.format(abconfscore=abconfscore)

@mic.route("/not_reported")
def not_reported():
    return '''
        <html>
            <title>Not Reported !!</title>
            <body>
            <h1 style="color:magenta;font-size:18px;">The IP address has not been reported. Thank You!</h1>
            <h1 style="color:green;font-size:18px">Please click here if you want to check another IP address</h1>
            </body>
        <html>
'''

@mic.route("/",methods = ['GET','POST'])
def malicious_ip_checker():
    if request.method=='POST':
        whois_listing=[]
        vt_malicious=0
        vt_malware=0
        url_ip=None
        url_ip=str(request.form["url_ip"])
        obj=MaliciousIPCheck()
        ip_addr=obj.resolving_ip(url_ip)
        session["IPADDR"]=ip_addr
        whois=obj.whois_info(ip_addr)
        abcfscore=None
        abipdb=None
        with open('/var/tmp/whoisinfo.json') as f:
            content=json.load(f)
        for i in range(len(content['nets'][0]['emails'])):
            whois_listing.append(content['nets'][0]['emails'][i])
        obj.virus_total(ip_addr)
        with open('/var/tmp/vt-info.json') as file1:
            vt_content=json.load(file1)
        vt_malicious=vt_content['data']['attributes']['total_votes']['malicious']
        for v in vt_content['data']['attributes']['last_analysis_results'].values():
            if v['result']=='malware':
                vt_malware+=1
        obj.abuse_ipdb(ip_addr)
        with open('/var/tmp/abuseaddresses.json') as f1:
            abipdb=json.load(f1)
        domn=abipdb['data']['domain']
        reported_times=abipdb['data']['totalReports']
        return '''
            <html>
                <body>
                    <title>Results</title>
                    <h1 style = "color:blue;font-size:16px;">IP address: {ip_addr}</h1`>
                    <p>Contact Emails from Whois:{whois_listing}</p>
                    <h1 style="color:red;font-size:18px;">Virus Total Information:</h1>
                    <h1 style="color:red;font-size:20px;">Malware Engines: {vt_malware}</h1>
                    <h1 style=color:red;font-size:20px;">Malicious Engines: {vt_malicious}</h1>         
                    <h1 style ="color:green;font-size:18px;">Abuse IP DB Information:</h1>
                    <h1 style="color:green;font-size:20px;">Domain: {domn}</h1>
                    <h1 style ="color:green;font-size:20px;">No. of times reported to AbuseIPDB: {reported_times}</h1>
                    <b>Do you want to report this IP to AbuseIPDB?</b>
                    <p style ="color:green:font-size:16px;">Note: An IP address can only be reported once in 15 minutes</p>
                
                    <form method="post" action="/">
                    <button type="submit" name="submit_yes" value="submit_yes"><a href=reported>Yes</a></button>
                    <button type="submit" name="submit_no" value="submit_no"><a href=not_reported>No</a></button>
                    </form>
                </body>
            </html>
        '''.format(ip_addr=ip_addr,whois_listing=whois_listing,vt_malicious=vt_malicious,vt_malware=vt_malware,domn=domn,reported_times=reported_times)  
    return render_template('index.html')

mic.run(debug=True)
