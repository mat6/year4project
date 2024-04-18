import nmap3,json,sys
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QLabel, QScrollArea, QGridLayout, QMainWindow, QWidget, QGridLayout,QLineEdit,QPushButton,QVBoxLayout

#remove empty results and empty fields
def removeEmptyResult(result):
    for key in list(result.keys()):
        if key.find('.') != -1:                                                         #check if entry is a host ( e.g: ip address x.x.x.x or domain name x.com)
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
        if key.find('.') != -1:
            host = {}
            host["address"] = key
            if "hostname" in result[key]:
                host["hostname"] = result[key]["hostname"][0]["name"]
            host["state"] = result[key]["state"]["state"]
            parsedResult[key] = host
    return parsedResult

#gui that displays results in window with scrollbar
def resultGUI(result):
    app = QApplication([])
    window = QScrollArea()
    window.setWindowTitle("Nmap Results")
    contents = QLabel(result)
    window.setWidget(contents)
    window.show()
    app.exec()

#regular ping scan
def pingScan(target):
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_ping_scan(target)
    removeEmptyResult(result)
    result = parsePing(result)
    result = json.dumps(result,indent=4)
    return result

#os scan REQUIRES ROOT
def osScan(target):
    nmap = nmap3.Nmap()
    result = nmap.nmap_os_detection(target)
    removeEmptyResult(result)
    result = json.dumps(result,indent=4)
    return result

#version scan
def versionScan(target):
    nmap = nmap3.Nmap()
    result = nmap.nmap_version_detection(target)
    removeEmptyResult(result)
    result = json.dumps(result,indent=4)
    return result

#top ports scan
def topPortScan(target):
    nmap = nmap3.Nmap()
    result = nmap.scan_top_ports(target)
    removeEmptyResult(result)
    result = json.dumps(result,indent=4)
    return result

def mainMenu():
    app = QApplication([])
    window = QScrollArea()
    window.setWindowTitle("Home Network Scanner")
    windowLayout = QGridLayout
    window.show()
    app.exec()

class homeScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.generalLayout = QVBoxLayout()
        self.setWindowTitle("Home Network Scanner")
        self.resize(1280,720)
        centralWidget = QWidget(self)
        centralWidget.setLayout(self.generalLayout)
        self.setCentralWidget(centralWidget)
        self._createDisplay()
        self._createButtons()
    
    def _createDisplay(self):
        self.display = QLineEdit()
        self.display.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.display.setReadOnly(True)
        self.generalLayout.addWidget(self.display)
    
    def _createButtons(self):
        self.buttonMap = {}
        options = ["Ping Scan","Operating System Scan","Version Scan","Top Ports Scan"]
        buttonsLayout = QGridLayout()
        for text in enumerate(options):
            self.buttonMap[text] = QPushButton(text)
            self.buttonMap[text].setFixedSize(50,50)
            buttonsLayout.addWidget(self.buttonMap[text])
        self.generalLayout.addLayout(buttonsLayout)

def main():
    homeScannerApp = QApplication([])
    homeScannerWindow = homeScanner()
    homeScannerWindow.show()
    sys.exit(homeScannerApp.exec())

main()