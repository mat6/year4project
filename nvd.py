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
    r = {}
    for cpe in result:
        print(cpe)
        try:
            r[cpe] = nvdlib.searchCVE(cpeName=cpe,key=key,limit=5)
        except:
            r[cpe] = "Not Found"
        for item in r:
            print(item)
    return(r)