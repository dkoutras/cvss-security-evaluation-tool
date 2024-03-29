from selenium import webdriver
from selenium.webdriver.common.by import By
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.firefox.service import Service
from bs4 import BeautifulSoup

import getopt, sys
import requests
import time
import subprocess
import getpass
import re

def protocolCVEListProduction(protocol): 
    #starting Base
    serverGrep = open(protocol, "r").read()
    
    print(serverGrep)
    #error handling in case of closed ports
    if serverGrep == '': 
        serverGrep = "gdveqfjqhbfuqej"
    
    serverCvesUrl = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query=' + serverGrep + '&search_type=all&isCpeNameSearch=false&cvss_version=3'
    
    serverPage = requests.get(serverCvesUrl)
    
    serverSoup = BeautifulSoup(serverPage.content, 'lxml')

    contentServerSoup = serverSoup.find('div', id = 'row')
    contentServerSoup2 = contentServerSoup.find('tbody')
    contentServerSoup3 = contentServerSoup2.findAll('th', nowrap = "nowrap")

    list = []

    for th in contentServerSoup3:
        b = th.find('a').text
        list.append(b)

    return list

def baseEnvScoreCalc(impactListCIA, protocol):
    driver = webdriver.Firefox(service=Service(GeckoDriverManager().install()))
    
    try:
        if protocol == "Smtp.txt":
            smtpServerCVEList = protocolCVEListProduction(protocol)
            domainCVEList = protocolCVEListProduction("Domain.txt")
            smtpCVEList = smtpServerCVEList + domainCVEList
            list = smtpCVEList
            ciaTable = ciaTableProductionSmtp(impactListCIA)
        elif protocol == "Ftp.txt":
            ftpServerCVEList = protocolCVEListProduction(protocol)
            list = ftpServerCVEList
            ciaTable = ciaTableProductionFtp(impactListCIA)
        elif protocol == "Http.txt":
            httpServerCVEList = protocolCVEListProduction(protocol)
            list = httpServerCVEList
            ciaTable = ciaTableProductionHttp(impactListCIA)
        else:
            print("Error occured")
    except Exception as e:
        print(str(e))

    # Strings from protocols[ftp,SMTP,HTTP] CIA impact table
    confidentiality = ciaTable[0]
    integrity = ciaTable[1]
    availability = ciaTable[2]

    for cve in list:
        # URLs
        CVE = cve
        print("\n")
        print(CVE)
        nistUrl = 'https://nvd.nist.gov/vuln/detail/' + CVE   
        calcUrl = 'https://www.first.org/cvss/calculator/'
        
        #starting Env
        page = requests.get(nistUrl)
        envSoup = BeautifulSoup(page.content, 'lxml')
        
        contentBaseNist = envSoup.find('a', id = 'Cvss3NistCalculatorAnchor')
        contentBaseCna = envSoup.find('a', id = 'Cvss3CnaCalculatorAnchor')

        if (contentBaseNist is not None and contentBaseCna is not None):
            contentBase = contentBaseNist
        elif (contentBaseCna is None):
            contentBase = contentBaseNist
        elif (contentBaseNist is None):
            contentBase = contentBaseCna
        else:
            print ("********")

        contentCVENist = envSoup.find('span', class_ = 'tooltipCvss3NistMetrics') 
        contentCVECna = envSoup.find('span', class_ = 'tooltipCvss3CnaMetrics') 

        if (contentCVENist is not None and contentCVECna is not None):
            contentCVE = contentCVENist
        elif (contentCVECna is None):
            contentCVE = contentCVENist
        elif (contentCVENist is None):
            contentCVE = contentCVECna
        else:
            print ("********")

        baseScore = contentBase.text
        cveVector = contentCVE.text
        
        version30 = '3.0'
        version31 = '3.1'

        if (version30 in cveVector):
            version = version30
        elif (version31 in cveVector):
            version = version31


        if ('AV:N' in cveVector):
            MAV = 'AV:N'
        elif ('AV:A' in cveVector):
            MAV = 'AV:A'
        elif ('AV:L' in cveVector):
            MAV = 'AV:L'
        else:
            MAV = 'AV:P' 

        print("\nBase Score:")
        print(baseScore) 
        print("\n" + cveVector)
        calcUrl += version + '#' + cveVector + '/M' + MAV  
        print("\n" + calcUrl)
        
        driver.get(calcUrl)  
           
        time.sleep(3)
        driver.find_element(By.XPATH, '//*[@id="MC_' + confidentiality + '_Label"]').click()
        time.sleep(2)
        driver.find_element(By.XPATH, '//*[@id="MI_' + integrity + '_Label"]').click()
        time.sleep(2)
        driver.find_element(By.XPATH, '//*[@id="MA_' + availability + '_Label"]').click()
        time.sleep(2)
        environmentalScoreNumber = driver.find_element(By.XPATH, '//*[@id="environmentalMetricScore"]')
        time.sleep(2)
        environmentalScoreSeverity = driver.find_element(By.XPATH, '//*[@id="environmentalSeverity"]')
        time.sleep(2)
        # maybe close window later
        #driver.minimize_window()
        
        print("\nEnvironmental Score:")
        try:
            print(environmentalScoreNumber.text)
            print(environmentalScoreSeverity.text)
        except Exception as e:
            print(str(e))
    
def securityScoreCalc(impactList):
    scoreDict = {"H" : 0.4, "L" : 0.2, "N" : 0.0}
    securityScore = 0.0
    try:    
        for key in impactList:
            if key in scoreDict.keys():
                print(scoreDict[key])
                securityScore += scoreDict[key]
        securityScore /= len(impactList)
    except Exception as e:
        print(str(e))
    #return round(securityScore, 1)
    return securityScore
     
def ciaTableProductionSmtp(smtpImpactList):
    smtpTableRelay = ["", "", ""]
    smtpTableStrangePort = ["", "", ""]
    smtpTableEnum = ["", "", ""]
    smtpAttacks = ["", "", ""]
    if smtpImpactList[0] == 'N':
        smtpTableRelay[0] = 'N'
        smtpTableRelay[1] = 'N'
        smtpTableRelay[2] = 'N'
    elif smtpImpactList[0] == 'H':
        smtpTableRelay[0] = 'H'
        smtpTableRelay[1] = 'H'
        smtpTableRelay[2] = 'L'
    
    if smtpImpactList[1] == 'N':
        smtpTableStrangePort[0] = 'N'
        smtpTableStrangePort[1] = 'N'
        smtpTableStrangePort[2] = 'N'
    elif smtpImpactList[1] == 'H':
        smtpTableStrangePort[0] = 'N'
        smtpTableStrangePort[1] = 'H'
        smtpTableStrangePort[2] = 'H'
    elif smtpImpactList[1] == 'L':
        smtpTableStrangePort[0] = 'N'
        smtpTableStrangePort[1] = 'L'
        smtpTableStrangePort[2] = 'L'
        
    if smtpImpactList[2] == 'N':
        smtpTableEnum[0] = 'N'
        smtpTableEnum[1] = 'N'
        smtpTableEnum[2] = 'N'
    elif smtpImpactList[2] == 'L':
        smtpTableEnum[0] = 'L'
        smtpTableEnum[1] = 'N'
        smtpTableEnum[2] = 'N'
    
    print("\n")
    print(smtpTableRelay)
    print(smtpTableStrangePort)
    print(smtpTableEnum)
    #Confidentiality
    smtpAttacks[0] = min(smtpTableRelay[0], smtpTableStrangePort[0], smtpTableEnum[0])
    #Integrity
    smtpAttacks[1] = min(smtpTableRelay[1], smtpTableStrangePort[1], smtpTableEnum[1])
    #Availability
    smtpAttacks[2] = min(smtpTableRelay[2], smtpTableStrangePort[2], smtpTableEnum[2])
    print("\nCIA impact table: ")
    print(smtpAttacks)
    return smtpAttacks

def ciaTableProductionFtp(ftpImpactList):
    ftpTableAnon = ["", "", ""]
    ftpTableBounce = ["", "", ""]
    ftpTableFirewall = ["", "", ""]
    ftpAttacks = ["", "", ""]
    if ftpImpactList[0] == 'N':
        ftpTableAnon[0] = 'N'
        ftpTableAnon[1] = 'N'
        ftpTableAnon[2] = 'N'
    elif ftpImpactList[0] == 'H':
        ftpTableAnon[0] = 'L'
        ftpTableAnon[1] = 'L'
        ftpTableAnon[2] = 'L'
    
    if ftpImpactList[1] == 'N':
        ftpTableBounce[0] = 'N'
        ftpTableBounce[1] = 'N'
        ftpTableBounce[2] = 'N'
    elif ftpImpactList[1] == 'L':
        ftpTableBounce[0] = 'L'
        ftpTableBounce[1] = 'L'
        ftpTableBounce[2] = 'L'
        
    if ftpImpactList[2] == 'N':
        ftpTableFirewall[0] = 'N'
        ftpTableFirewall[1] = 'N'
        ftpTableFirewall[2] = 'N'
    elif ftpImpactList[2] == 'H':
        ftpTableFirewall[0] = 'N'
        ftpTableFirewall[1] = 'H'
        ftpTableFirewall[2] = 'H'
    
    print("\n")
    print(ftpTableAnon)
    print(ftpTableBounce)
    print(ftpTableFirewall)
    #Confidentiality
    ftpAttacks[0] = min(ftpTableAnon[0], ftpTableBounce[0], ftpTableFirewall[0])
    #Integrity
    ftpAttacks[1] = min(ftpTableAnon[1], ftpTableBounce[1], ftpTableFirewall[1])
    #Availability
    ftpAttacks[2] = min(ftpTableAnon[2], ftpTableBounce[2], ftpTableFirewall[2])
    print("\nCIA impact table: ")
    print(ftpAttacks)
    return ftpAttacks

def ciaTableProductionHttp(httpImpactList):
    httpTableSsl = ["", "", ""]
    httpTableCert = ["", "", ""]
    httpTableRef = ["", "", ""]
    httpAttacks = ["", "", ""]
    if httpImpactList[0] == 'N':
        httpTableSsl[0] = 'N'
        httpTableSsl[1] = 'N'
        httpTableSsl[2] = 'N'
    elif httpImpactList[0] == 'H':
        httpTableSsl[0] = 'H'
        httpTableSsl[1] = 'H'
        httpTableSsl[2] = 'H'
    
    if httpImpactList[1] == 'N':
        httpTableCert[0] = 'N'
        httpTableCert[1] = 'N'
        httpTableCert[2] = 'N'
    elif httpImpactList[1] == 'H':
        httpTableCert[0] = 'H'
        httpTableCert[1] = 'H'
        httpTableCert[2] = 'L'
        
    if httpImpactList[2] == 'N':
        httpTableRef[0] = 'N'
        httpTableRef[1] = 'N'
        httpTableRef[2] = 'N'
    elif httpImpactList[2] == 'L':
        httpTableRef[0] = 'L'
        httpTableRef[1] = 'L'
        httpTableRef[2] = 'N'
    
    print("\n")
    print(httpTableSsl)
    print(httpTableCert)
    print(httpTableRef)
    #Confidentiality
    httpAttacks[0] = min(httpTableSsl[0], httpTableCert[0], httpTableRef[0])
    #Integrity
    httpAttacks[1] = min(httpTableSsl[1], httpTableCert[1], httpTableRef[1])
    #Availability
    httpAttacks[2] = min(httpTableSsl[2], httpTableCert[2], httpTableRef[2])
    print("\nCIA impact table: ")
    print(httpAttacks)
    return httpAttacks

def parseOutputSmtpTxt(dictSmtpOpenRelay, dictSmtpStrangePort, dictSmtpEnum, smtpFileNames):   
    # opening 3 text files
    fileOpenRelay = open(smtpFileNames[0], "r")
    fileStrangePort = open(smtpFileNames[1], "r")
    fileEnum = open(smtpFileNames[2], "r")
    # read each file's content
    readfileOpenRelay = fileOpenRelay.read()
    readfileStrangePort = fileStrangePort.read()
    readfileEnum = fileEnum.read()
    resultfileOpenRelay = ""
    resultfileStrangePort = ""
    resultfileEnum = ""
    try:
        for key1 in dictSmtpOpenRelay.keys(): 
            if key1 in readfileOpenRelay: 
                print('\nString', key1, 'found in file', smtpFileNames[0])
                resultfileOpenRelay += dictSmtpOpenRelay[key1]
            else: 
                print('\nString', key1 , 'not found in file', smtpFileNames[0],'\n') 
                
        for key2 in dictSmtpStrangePort.keys(): 
            if key2 in readfileStrangePort: 
                print('\nString', key2, 'found in file', smtpFileNames[1])
                resultfileStrangePort += dictSmtpStrangePort[key2]
                if resultfileStrangePort == 'H': break
            else: 
                print('\nString', key2 , 'not found in file', smtpFileNames[1],'\n')
        #if keys not in dict get N
        if resultfileStrangePort == "" : resultfileStrangePort = 'N'

        for key3 in dictSmtpEnum.keys(): 
            if key3 in readfileEnum: 
                print('\nString', key3, 'found in file', smtpFileNames[2])
                resultfileEnum += dictSmtpEnum[key3]
            else: 
                print('\nString', key3 , 'not found in file', smtpFileNames[2],'\n')
        if (resultfileEnum == "LN" or resultfileEnum == "LNN") : resultfileEnum = "N"
        if (resultfileEnum == "LL" or resultfileEnum == "LNL" or resultfileEnum == "NL") : resultfileEnum = "L"
    except Exception as e:
        print(str(e))
    # closing the files
    fileOpenRelay.close()
    fileStrangePort.close()
    fileEnum.close() 
    #handle the N N N with a message 
    if (resultfileOpenRelay == "N" and resultfileStrangePort == "N" and resultfileEnum == "N"): 
        print('\nYour system is not vulnerable to OpenRelay, StrangePort and Enum attacks. So, your env score may be "0".\nThis score may be fictitious because your system may be exposed to other attacks not considered in this version of the tool.')
    smtpImpactList = [resultfileOpenRelay, resultfileStrangePort, resultfileEnum]
    return smtpImpactList

def parseOutputFtpTxt(dictFtpAnon, dictFtpBounce, dictFtpFirewall, ftpFileNames):   
    # opening 3 text files
    fileAnon = open(ftpFileNames[0], "r")
    fileBounce = open(ftpFileNames[1], "r")
    fileFirewall = open(ftpFileNames[2], "r")
    # read each file's content
    readfileAnon = fileAnon.read()
    readfileBounce = fileBounce.read()
    readfileFirewall = fileFirewall.read()
    resultfileAnon = ""
    resultfileBounce = ""
    resultfileFirewall = ""
    try:
        for key1 in dictFtpAnon.keys(): 
            if key1 in readfileAnon: 
                print('\nString', key1, 'found in file', ftpFileNames[0])
                resultfileAnon += dictFtpAnon[key1]
            else: 
                print('\nString', key1 , 'not found in file', ftpFileNames[0],'\n') 
                resultfileAnon = 'N'

        for key2 in dictFtpBounce.keys(): 
            if key2 in readfileBounce: 
                print('\nString', key2, 'found in file', ftpFileNames[1])
                resultfileBounce += dictFtpBounce[key2]
            else: 
                print('\nString', key2 , 'not found in file', ftpFileNames[1],'\n')
                resultfileBounce = 'N'

        for key3 in dictFtpFirewall.keys(): 
            if key3 in readfileFirewall: 
                print('\nString', key3, 'found in file', ftpFileNames[2])
                resultfileFirewall += dictFtpFirewall[key3]
            else: 
                print('\nString', key3 , 'not found in file', ftpFileNames[2],'\n')
                resultfileFirewall = 'N'

        if resultfileFirewall == 'NN' : resultfileFirewall = 'N'
    except Exception as e:
        print(str(e))
    # closing the files
    fileAnon.close()
    fileBounce.close()
    fileFirewall.close() 
    #handle the N N N with a message 
    if (resultfileAnon == "N" and resultfileBounce == "N" and resultfileFirewall == "N"): 
        print('\nYour system is not vulnerable to Anon, Bounce and Firewall Bypass attacks. So, your env score may be "0".\nThis score may be fictitious because your system may be exposed to other attacks not considered in this version of the tool.')
    ftpImpactList = [resultfileAnon, resultfileBounce, resultfileFirewall]
    return ftpImpactList

def parseOutputHttpTxt(dictHttpSsl, dictHttpCert, dictHttpRef, httpFileNames):
    # opening 3 text files
    fileSsl = open(httpFileNames[0], "r")
    fileCert = open(httpFileNames[1], "r")
    fileRef = open(httpFileNames[2], "r")
    # read each file's content
    readfileSsl = fileSsl.read()
    readfileCert = fileCert.read()
    readfileRef = fileRef.read()
    resultfileSsl = ""
    resultfileCert = ""
    resultfileRef = ""
    try:
        for key1 in dictHttpSsl.keys(): 
            if key1 in readfileSsl: 
                print('\nString', key1, 'found in file', httpFileNames[0])
                resultfileSsl += dictHttpSsl[key1]
            else: 
                print('\nString', key1 , 'not found in file', httpFileNames[0],'\n') 
        if resultfileSsl == 'NN' : resultfileSsl = 'N'

        for key2 in dictHttpCert.keys(): 
            if key2 in readfileCert: 
                print('\nString', key2, 'found in file', httpFileNames[1])
                resultfileCert += dictHttpCert[key2]

        for key3 in dictHttpRef.keys(): 
            if key3 in readfileRef: 
                print('\nString', key3, 'found in file', httpFileNames[2])
                resultfileRef += dictHttpRef[key3] 

        if resultfileSsl == '' : resultfileSsl = 'N'
        if resultfileCert == '' : resultfileCert = 'N'
        if resultfileRef == '' : resultfileRef = 'N'
    except Exception as e:
        print(str(e))
    # closing the files
    fileSsl.close()
    fileCert.close()
    fileRef.close() 
    #handle the N N N with a message 
    if (resultfileSsl == "N" and resultfileCert == "N" and resultfileRef == "N"): 
        print("\nYour system has no vulnerabilities that are related to Ssl and certificates. So, the system's environmental score may be '0'.\nThis score may be fictitious because your system may be exposed to other attacks not colnsidered in this version of the tool.")
    httpImpactList = [resultfileSsl, resultfileCert, resultfileRef]
    return httpImpactList

if __name__ == "__main__":
    argumentList = sys.argv[1:]
    options = "s:f:t:a:h"
    long_options = ["smtp =", "ftp =", "http =", "all ="]

    #SMTP THREAT LIST
    dictSmtpOpenRelay = {"Server is an open relay" : "H", "Server doesn't seem to be an open relay" : "N"}
    dictSmtpStrangePort = {"unusual port: possible malware" : "H", "open  unknown" : "L"} 
    dictSmtpEnum = {"|_  " : "L", "Couldn't find" : "N", "unhandled status" : "L"} 

    #FTP THREAT LIST
    dictFtpAnon = {"Anonymous FTP login allowed" : "H"}
    dictFtpBounce = {"bounce working!" : "L"}
    dictFtpFirewall = {"Firewall vulnerable to bypass" : "H", "Failed to resolve" : "N"}

    #HTTP THREAT LIST # 
    dictHttpSsl = {"closed https" : "H", "SSLv2 supported" : "L", "TLSv1.0:" : "N", "TLSv1.2:" : "N"}
    dictHttpCert = {"certificate_lifespan" : "H", "path validation failed" : "L", "OK - Order is valid" : "N"}
    dictHttpRef = {"Couldn't find any cross-domain scripts" : "N", "Spidering limited to" : "L"}

    try: 
        arguments, values = getopt.getopt(argumentList, options, long_options)
        
        for currentArgument, currentValue in arguments:
            try:
                if currentArgument in ("-s", "--smtp"):
                    smtpFileNames = ["openRelayOut.txt", "strangePortOut.txt", "enumOut.txt"]
                    print ("SMTP protocol security test")
                    print (("IP is: % s") % (currentValue))
                    try:
                        processSmtp = subprocess.Popen(["scriptSMTP.sh", currentValue], shell=True)
                        processSmtp.wait()
                    except Exception as e:
                        print(str(e))                  
                    smtpImpactList = parseOutputSmtpTxt(dictSmtpOpenRelay, dictSmtpStrangePort, dictSmtpEnum, smtpFileNames)
                    securityScore = securityScoreCalc(smtpImpactList)
                    print("\nThe impact of the attacks in the smtp server is ")
                    print(smtpImpactList)
                    print("\nSmtp server security score is ")
                    print(securityScore)
                    if securityScore < 0.2:
                        print("\nSecurity is strong")
                    elif securityScore <= 0.3:
                        print("\nSecurity is moderate")
                    else:
                        print("\nSecurity is weak")
                    protocol = "Smtp.txt"
                    baseEnvScoreCalc(smtpImpactList, protocol)
                elif currentArgument in ("-f", "--ftp"):
                    ftpFileNames = ["serverInfo.txt", "bounceOut.txt", "firewallOut.txt"]
                    print ("FTP protocol security tes")
                    print (("IP is: % s") % (currentValue))
                    processFtp = subprocess.Popen(["scriptFTP.sh", currentValue], shell=True)
                    processFtp.wait()
                    ftpImpactList = parseOutputFtpTxt(dictFtpAnon, dictFtpBounce, dictFtpFirewall, ftpFileNames)
                    print("\nThe impact of the attacks in the ftp server is ")
                    print(ftpImpactList)
                    securityScore = securityScoreCalc(ftpImpactList)
                    print("\nThe impact of the attacks in the Ftp server is ")
                    print(ftpImpactList)
                    print("\nFtp server security score is ")
                    print(securityScore)
                    if securityScore < 0.12:
                        print("\nSecurity is strong")
                    elif securityScore <= 0.3:
                        print("\nSecurity is moderate")
                    else:
                        print("\nSecurity is weak")
                    protocol = "Ftp.txt"
                    baseEnvScoreCalc(ftpImpactList, protocol)
                elif currentArgument in ("-t", "--http"):
                    httpFileNames = ["sslOut.txt", "certOut.txt", "refOut.txt"]
                    print ("HTTP")    
                    print (("IP is: % s") % (currentValue))
                    processHttp = subprocess.Popen(["scriptHTTP.sh", currentValue], shell=True)
                    processHttp.wait()
                    httpImpactList = parseOutputHttpTxt(dictHttpSsl, dictHttpCert, dictHttpRef, httpFileNames)
                    print("\nThe impact of the attacks in the http server is ")
                    print(httpImpactList)
                    securityScore = securityScoreCalc(httpImpactList)
                    print("\nThe impact of the attacks in the Http server is ")
                    print(httpImpactList)
                    print("\nHttp server security score is ")
                    print(securityScore)
                    if securityScore < 0.2:
                        print("\nSecurity is strong")
                    elif securityScore <= 0.3:
                        print("\nSecurity is moderate")
                    else:
                        print("\nSecurity is weak")
                    protocol = "Http.txt"
                    baseEnvScoreCalc(httpImpactList, protocol)
                elif currentArgument in ("-a", "--all"):
                    smtpFileNames = ["openRelayOut.txt", "strangePortOut.txt", "enumOut.txt"]
                    ftpFileNames = ["serverInfo.txt", "bounceOut.txt", "firewallOut.txt"]
                    httpFileNames = ["sslOut.txt", "certOut.txt", "refOut.txt"]
                    print ("ALL")  
                    print ("USE AT YOUR OWN RISK")                    
                    print (("IP is: % s") % (currentValue))
                    processSmtp = subprocess.Popen(["scriptSMTP.sh", currentValue], shell=True)
                    time.sleep(1)
                    processFtp = subprocess.Popen(["scriptFTP.sh", currentValue], shell=True)
                    time.sleep(1)
                    processHttp = subprocess.Popen(["scriptHTTP.sh", currentValue], shell=True)
                    processSmtp.wait()
                    processFtp.wait()
                    processHttp.wait()
                    smtpImpactList = parseOutputSmtpTxt(dictSmtpOpenRelay, dictSmtpStrangePort, dictSmtpEnum, smtpFileNames)
                    ftpImpactList = parseOutputFtpTxt(dictFtpAnon, dictFtpBounce, dictFtpFirewall, ftpFileNames)
                    httpImpactList = parseOutputHttpTxt(dictHttpSsl, dictHttpCert, dictHttpRef, httpFileNames)
                    print("\nThe impact of the attacks in the smtp server is ")
                    protocol = "Smtp.txt"
                    print(smtpImpactList)
                    baseEnvScoreCalc(smtpImpactList, protocol)
                    print("\nThe impact of the attacks in the ftp server is ")
                    protocol = "Ftp.txt"
                    print(ftpImpactList)
                    baseEnvScoreCalc(ftpImpactList, protocol)
                    print("\nThe impact of the attacks in the http server is ")
                    protocol = "Http.txt"
                    print(httpImpactList)
                    baseEnvScoreCalc(httpImpactList, protocol)
                elif currentArgument in ("-h", "--help"):
                    print ("Please read the README.md file !\n install python3\n install pip\npip install -r requirements.txt\ninstall nmap\ninstall sslyze\ninstall go language\ninstall git bash\nexample of usage : python Aness.py -s <ip>  \n//-s for the smtp protocol\n//-f for the ftp protocol\n//-t for the http protocol\n//-a for all the protocols\n//-h for help ") 
            except Exception as e:
                print(str(e))
                sys.exit()
    except getopt.error as err:
        # output error, and return with an error code
        print (str(err))
        print("Type -h or --help for help")
        sys.exit() 

print("End")
