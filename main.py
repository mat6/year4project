import nmap,nvd,os,ctypes
from flask import Flask, render_template, request, redirect
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'WkaDs7TG5]>zxb*USJe^Ma'

class scanResults():
    pingResults = {}
    versionResults = {}
    osResults = {}
    cpes = {}

allResults = scanResults()

def makeLogDirs():
    if not os.path.exists("results"):
        os.mkdir("results")
    if not os.path.exists("logs"):
        os.mkdir("logs")

@app.route("/")
def index():
    message = "Sudo"
    try:                                #check if the user is root and make log directories
        admin = os.getuid() == 0
        original_umask = os.umask(0)
        makeLogDirs()
        os.umask(original_umask)
    except AttributeError:
        admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        message = "Admin"
        makeLogDirs()
    if admin:
        selfIp = nmap.getSelfIp()                       #grab own ip to determine default network to put in input box
        index = selfIp.rfind(".")
        if index != - 1:
            networkIp = selfIp[0:index+1] + "0/24"
            selfIp = "is " + selfIp
        else:
            selfIp = "could not be determined"
            networkIp = ""
        return render_template("pingScan.html",selfIp=selfIp,networkIp=networkIp)
    else:
        return render_template("noRoot.html",message=message)

@app.route("/pingResults",methods=("GET","POST"))
def pingResult():
    if request.method == "POST":
        target = request.form["target"]
        result = nmap.pingScan(target)
        allResults.pingResults = result
        if result:
            return render_template("pingResults.html",result=result,target=target)
        else:
            return render_template("emptyPing.html",target=target)
    else: return redirect("/")

@app.route("/versionScan",methods=("GET","POST"))
def versionScan():
    if request.method == "POST":
        results = {}
        for target in request.form:
            result = nmap.verScan(target)
            results[target] = result
            allResults.versionResults.update(results)
        return render_template("versionScan.html",result=results)
    else: return redirect("/")

@app.route("/osScan",methods=("GET","POST"))
def osScan():
    if request.method == "POST":
        results = {}
        for target in request.form:
            result = nmap.osScan(target)
            results = results | result
            allResults.cpes[target] = nmap.getCPEOS(result)
        allResults.osResults = results
        results = nmap.parseOS(results)
        return render_template("osScan.html",result=results)
    else: return redirect("/")

@app.route("/vulnCheck",methods=("GET","POST"))
def vulnCheck():
    if request.method == "POST":
        results = {}
        resultsLog = open("results/results " + datetime.today().strftime("%d-%m-%Y") + ".log","a")
        resultsLog.write(str(datetime.now()) + " - Results of Home Network Security Analyzer - \n")
        for hosts in request.form:
            if hosts in allResults.cpes:
                cves = nvd.getCVE(allResults.cpes[hosts])
                results[hosts] = cves
        results = nvd.parseCVE(results)
        
        for host in results:
            resultsLog.write("---" + host + "---\n")
            for cpe in results[host]:
                resultsLog.write("CPE: " + cpe + "\n")
                for cve in results[host][cpe]:
                    print(cve)
                    resultsLog.writelines("CVE: " + str(cve) + "\n\n")
        resultsLog.write("\n-------------\n")
        resultsLog.close
        return render_template("vulnCheck.html",result=results)
    else: return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
