import nvdlib,json
from datetime import datetime

def getKey():
    try:
        file = open("apikey.txt")
        key = file.read()
        file.close()
        return key
    except Exception as err:
        print("Error with getting API key: ", err)
        return ""

def getCVE(result):
    nvdLog = open("logs/nvd " + datetime.today().strftime("%d-%m-%Y") + ".log","a")
    key = getKey()
    r = {}
    nvdLog.write(str(datetime.now()) + ": CPEs :\n")
    for cpe in result:
        try:
            r[cpe] = nvdlib.searchCVE(cpeName=cpe,key=key,limit=5)
        except:
            r[cpe] = "Not Found"
        for item in r:
            nvdLog.writelines("\n" + item + ":\n")
            for sub in r[item]:
                nvdLog.writelines(str(sub))
    nvdLog.write("\n-------------\n")
    nvdLog.close()
    return(r)

def parseCVE(input):
    parsedResult = {}
    for host in input:
        parsedCpes = {}
        for cpe in input[host]:
            cpeList = []
            if input[host][cpe] != "Not Found":
                for cve in input[host][cpe]:
                    a = nvdlib.cve
                    cveEntry = {}
                    cveEntry["id"] = cve.id
                    cveEntry["serv"] = cve.v2severity
                    cveEntry["desc"] = cve.descriptions[0].value
                    cveEntry["status"] = cve.vulnStatus
                    cveEntry["url"] = cve.url
                    cpeList.append(cveEntry)
            else:
                cpeList.append("Not Found")
            parsedCpes[cpe] = cpeList
        parsedResult[host] = parsedCpes
    print(parsedResult)
    return parsedResult