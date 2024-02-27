import nmap,nvd
from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField

app = Flask(__name__)
app.config['SECRET_KEY'] = 'WkaDs7TG5]>zxb*USJe^Ma'

class pingForm(FlaskForm):
    target = StringField("Target")
    submit = SubmitField("Start Scan")

class scanResults():
    pingResults = {}
    versionResults = {}
    osResults = {}
    cpes = {}

allResults = scanResults()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/pingScan")
def ping():
    form = pingForm()
    return render_template("pingScan.html",form=form)

@app.route("/pingResults",methods=("GET","POST"))
def pingResult():
    if request.method == "POST":
        target = request.form["target"]
        result = nmap.pingScan(target)
        allResults.pingResults = result
        print(result)
        return render_template("pingResults.html",result=result)
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
            results[target] = result
            allResults.cpes[target] = nmap.parseOS(result)
        allResults.osResults = results
        return render_template("osScan.html",result=results)
    else: return redirect("/")

@app.route("/vulnCheck",methods=("GET","POST"))
def vulnCheck():
    if request.method == "POST":
        results = {}
        for hosts in request.form:
            if hosts in allResults.cpes:
                    results[hosts] = nvd.getCVE(allResults.cpes[hosts])   
        return render_template("vulnCheck.html",result=results)
    else: return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
