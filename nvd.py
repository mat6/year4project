import nvdlib
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
    key = getKey()
    for host in result:
        print("CVEs of ", host, ": ")
        for cpe in result[host]:
            print(cpe)
            r = nvdlib.searchCVE(cpeName=cpe,key=key,limit=5)
            for item in r:
                print(item)