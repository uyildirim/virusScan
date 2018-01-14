import requests
import sys
import hashlib


if len(sys.argv) <= 2:
    print "Kullanim: python virus_scan.py online myfile.exe"
if len(sys.argv) > 2:
    md5 = hashlib.md5(open(sys.argv[2],'rb').read())
    resource = md5.hexdigest()
    apikey = "0edf22ae019a4b23eb308aa9bd1ebe0b4830e2ea4dd43f0a3ddba2a8b326dc2f"
    # resource = '44d88612fea8a8f36de82e1278abb02d'
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': resource}

    response = requests.get(url, params=params)
    resjson = response.json()
    # print resjson["scans"]

    # print resjson["scans"]
    dizi = []
    for s in resjson["scans"]:
        dizi.append(s)
    for d in dizi:
        print str(d) + " : " + str(resjson["scans"][d]["result"])


    if (resjson["response_code"] == 0):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        myfile = sys.argv[2]
        params = {'apikey': apikey}
        files = {'file': (myfile, open(myfile, 'rb'))}
        response = requests.post(url, files=files, params=params)
        print(response.json())
