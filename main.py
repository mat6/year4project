import nmap,nvd
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
pingResult = {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/pingScan",methods=("GET","POST"))
def ping():
    if request.method == "POST":
      target = request.form["target"]
      pingResult = nmap.pingScan(target)
      return render_template("pingResults.html",result=pingResult)
    return render_template("pingScan.html")

@app.route("/versionScan")
def versionScan():
    return render_template("versionScan.html",result=results)

if __name__ == "__main__":
    app.run(debug=True)
