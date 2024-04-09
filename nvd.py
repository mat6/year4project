import nvdlib,json
from datetime import datetime

#get api key from file for use with nvd api
def getKey():
    try:
        file = open("apikey.txt")
        key = file.read()
        file.close()
        return key
    except Exception as err:
        print("Error with getting API key: ", err)
        return ""

#get cve of given cpes with nvdlib
def getCVE(result):
    nvdLog = open("logs/nvd " + datetime.today().strftime("%d-%m-%Y") + ".log","a")
    key = getKey()
    cve = {}
    nvdLog.write(str(datetime.now()) + ": CPEs :\n")
    for cpe in result:
        try:
            curCpe = nvdlib.searchCVE(cpeName=cpe,key=key,limit=5)      #try to find cpe with exact search
        except:
            try:
                curCpe = nvdlib.searchCVE(virtualMatchString=cpe,key=key,limit=5)       #if exact search fails to find a cpe try a looser search
            except Exception as error:
                nvdLog.write("Error in retrieving CVEs for CPE - " + str(cpe) + " - Exception: " + str(error) + "\n")
                curCpe = "CPE Not Found"                              #catch exception for cpe not found
        if not curCpe:
            curCpe = "No CVEs found for CPE"        #for cases where CPE exists but has no CVE associated
        cve[cpe] = curCpe
        for item in cve:
            nvdLog.writelines("\n" + item + ":\n")
            for sub in cve[item]:
                nvdLog.writelines(str(sub))
    nvdLog.write("\n-------------\n")
    nvdLog.close()
    return(cve)

#get the most important information out of resulting cves
def parseCVE(input):
    parsedResult = {}
    for host in input:
        parsedCpes = {}
        for cpe in input[host]:
            cpeList = []
            if input[host][cpe] != "CPE Not Found" and input[host][cpe] != "No CVEs found for CPE":
                for cve in input[host][cpe]:
                    cveEntry = {}
                    cveEntry["ID"] = cve.id
                    cveEntry["Severity"] = cve.v2severity
                    cveEntry["Description"] = cve.descriptions[0].value
                    cveEntry["Stauts"] = cve.vulnStatus
                    cveEntry["NVD Url"] = cve.url
                    references = cve.references
                    refUrls = []
                    for item in references:
                        refUrls.append(item.url)
                    cveEntry["References to Advisories, Solutions, and Tools"] = refUrls
                    cpeList.append(cveEntry)
            else:
                cveEntry = {"Error" : input[host][cpe]}
                cpeList.append(cveEntry)
            parsedCpes[cpe] = cpeList
        parsedResult[host] = parsedCpes
    return parsedResult