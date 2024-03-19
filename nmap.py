import nmap3, json
from datetime import datetime


def writeLog(result,scantype):
    nmapLog = open("logs/nmap " + datetime.today().strftime("%d-%m-%Y") + ".log","a")
    nmapLog.write(str(datetime.now()) + ": " + scantype + ":\n")
    nmapLog.writelines(json.dumps(result,indent=4))
    nmapLog.write("\n-------------\n")
    nmapLog.close()
    
#remove empty results and empty fields
def removeEmptyResult(result):
    for key in list(result.keys()):
        if '.' in key:                                                         #check if entry is a host ( e.g: ip address x.x.x.x or domain name x.com)
            if "state" in "state" in result[key]:
                if result[key]["state"]["state"] == "down":                             #remove hosts that are down
                    result.pop(key)
                    continue
            for subkey in list(result[key].keys()):
                if ((result[key][subkey] is None) or (len(result[key][subkey]) == 0)):  #remove empty fields from result
                    result[key].pop(subkey)

#parse ping results
def parsePing(result):
    parsedResult = {}
    for key in list(result.keys()):
        if '.' in key:
            host = {}
            host["address"] = key
            if "hostname" in result[key]:
                host["hostname"] = result[key]["hostname"][0]["name"]
            host["state"] = result[key]["state"]["state"]
            parsedResult[key] = host
    return parsedResult

#get cpe from version scan
def parseVersion(result):
    entries = []
    for key in result:
        if '.' in key:
            for subkey in result[key]["ports"]:
                if "cpe" in subkey:
                    for entry in subkey["cpe"]:
                        if not entry["cpe"] == "cpe:/o:linux:linux_kernel":
                            entries.append(entry["cpe"].replace("/","2.3:"))
    return entries

#get cpe from os scan
def getCPEOS(result):
    entries = []
    for key in result:
        if '.' in key:
            count = 0
            for subkey in result[key]["osmatch"]:
                if count >= 5: 
                    break
                if "cpe" in subkey:
                    entries.append(subkey["cpe"].replace("/","2.3:"))
                    count += 1
            for subkey in result[key]["ports"]:
                if "cpe" in subkey and subkey["cpe"]:
                    entries.append(subkey["cpe"].replace("/","2.3:"))
    return entries

def parseOS(result):
    parsedResult = {}
    for key in result:
        count = 0
        entries = []
        for os in result[key][key]["osmatch"]:
            if count >= 5:
                break
            entry = os["name"] + " - Accuracy:" + os["accuracy"]
            entries.append(entry)
            count += 1
        for subkey in result[key][key]["ports"]:
            if "cpe" in subkey and subkey["cpe"]:
                    entries.append(subkey["cpe"].replace("/","2.3:"))
        parsedResult[key] = entries
    return parsedResult

#regular ping scan
def pingScan(target):
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_ping_scan(target)
    removeEmptyResult(result)
    writeLog(result,"Ping Scan")
    result = parsePing(result)
    return result

#os scan REQUIRES ROOT
def osScan(target):
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