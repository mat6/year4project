import nmap3, json,socket
from datetime import datetime

#get interal ip of host machine 
def getSelfIp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0)
    try:
        sock.connect(('192.168.1.1', 1))
        addr = sock.getsockname()[0]
    except Exception:
        addr = 'Address Not Found'
    finally:
        sock.close()
    return addr

def writeLog(result,scantype):
    nmapLog = open("logs/nmap " + datetime.today().strftime("%d-%m-%Y") + ".log","a")
    nmapLog.write(str(datetime.now()) + ": " + scantype + ":\n")
    nmapLog.writelines(json.dumps(result,indent=4))
    nmapLog.write("\n-------------\n")
    nmapLog.close()
    
#remove empty results and empty fields
def removeEmptyResult(result):
    for key in list(result.keys()):
        if '.' in key:                  #check if entry is a host ( e.g: ip address x.x.x.x or domain name x.com)
            if "state" in "state" in result[key]:
                if result[key]["state"]["state"] == "down":     #remove hosts that are down
                    result.pop(key)
                    continue
            for subkey in list(result[key].keys()):
                if ((result[key][subkey] is None) or (len(result[key][subkey]) == 0)):  #remove empty fields from result
                    result[key].pop(subkey)

def removeDupe(result):
    macList = []
    for key in list(result.keys()):
        if '.' in key:
            if "macaddress" in result[key]:
                mac = result[key]["macaddress"]["addr"]
                if mac not in macList:
                    macList.append(mac)
                    continue
                else:
                    result.pop(key)

#parse ping results, returns dict of target : dict of address,hostname and state
def parsePing(result):
    parsedResult = {}
    for key in list(result.keys()):
        if '.' in key:                   #check if entry is a host ( e.g: ip address x.x.x.x or domain name x.com)
            host = {}
            host["address"] = key
            if "hostname" in result[key]:                               #check for hostnames and include them if present
                host["hostname"] = result[key]["hostname"][0]["name"]
            host["state"] = result[key]["state"]["state"]               #state of host (up or down)
            parsedResult[key] = host
    return parsedResult

#get cpe from version scan, return dict of all cpe
def parseVersion(result):
    entries = []
    for key in result:
        if '.' in key:                          #check if entry is a host ( e.g: ip address x.x.x.x or domain name x.com)
            for subkey in result[key]["ports"]:
                if "cpe" in subkey:
                    for entry in subkey["cpe"]:
                        #if not entry["cpe"] == "cpe:/o:linux:linux_kernel":
                            entries.append(entry["cpe"].replace("/","2.3:")) #edit cpe returned by nmap for use with nvd api
    return entries

#get cpe of os and services found on ports from os scan 
def getCPEOS(result):
    entries = []
    for key in result:
        if '.' in key:                          #check if entry is a host ( e.g: ip address x.x.x.x or domain name x.com)
            count = 0
            if "osmatch" in result[key]:            #get cpes of top 5 unique OS
                for os in result[key]["osmatch"]:
                    if count >= 5: 
                        break
                    if "cpe" in os:
                        cpe = os["cpe"].replace("/","2.3:")
                        entries.append(cpe)
                        if cpe not in entries:
                            count += 1
            if "ports" in result[key]:                      #get cpe of all port services
                for port in result[key]["ports"]:
                    if "cpe" in port and port["cpe"]:
                        entries.append(port["cpe"].replace("/","2.3:"))
    return entries

#parse OS results for display in webpage
def parseOS(result):
    parsedResult = {}
    for key in result:
        if "." in key:
            count = 0
            entries = []
            if "osmatch" in result[key]:
                for os in result[key]["osmatch"]:          #get cpes of top 5 unique OS
                    if count >= 5:
                        break
                    entry = os["name"] + " - Accuracy:" + os["accuracy"] + " - CPE:"
                    if "cpe" in os:
                        entry += os["cpe"]
                        find = [x for x in entries if os["cpe"] in x]           #increase count if cpe isn't already present
                        if not find:
                            count += 1
                    else:
                        entry += "No CPE Found"
                    entries.append(entry)
            if "ports" in result[key]:                 #get any cpes of services running
                for subkey in result[key]["ports"]:
                    if "cpe" in subkey and subkey["cpe"]:
                            entries.append(subkey["cpe"])
            if entries:
                parsedResult[key] = entries
            else:
                parsedResult[key] = ["OS cound not be identified"]
    return parsedResult

#regular ping scan
def pingScan(target):
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_ping_scan(target)
    removeEmptyResult(result)
    removeDupe(result)
    writeLog(result,"Ping Scan")
    result = parsePing(result)
    return result

#os scan REQUIRES ROOT
def osScan(target):
    print(target)
    nmap = nmap3.Nmap()
    result = nmap.nmap_os_detection(target)
    removeEmptyResult(result)
    writeLog(result,"OS Scan")
    return result

#version scan
def verScan(target):
    nmap = nmap3.Nmap()
    result = nmap.nmap_version_detection(target)
    removeEmptyResult(result)
    writeLog(result,"Version Scan")
    return result

#top ports scan
def topPortsScan(target):
    nmap = nmap3.Nmap()
    result = nmap.scan_top_ports(target)
    removeEmptyResult(result)
    writeLog(result,"Top Ports Scan")
    return result