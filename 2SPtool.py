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

def baseEnvScoreCalc(impactListCIA):
    driver = webdriver.Firefox(service=Service(GeckoDriverManager().install()))
    
    #starting Base
    smtpGrep = open("Smtp.txt", "r").read()
    domainGrep = open("Domain.txt", "r").read()
    print (smtpGrep)
    print (domainGrep)
    #error handling in case of closed ports
    
    domainCvesUrl = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query=' + domainGrep + '&search_type=all&isCpeNameSearch=false&cvss_version=3'
    smtpCvesUrl = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query=' + smtpGrep + '&search_type=all&isCpeNameSearch=false&cvss_version=3'
    
    domainPage = requests.get(domainCvesUrl)
    smtpPage = requests.get(smtpCvesUrl)
    
    domainSoup = BeautifulSoup(domainPage.content, 'lxml')
    smtpSoup = BeautifulSoup(smtpPage.content, 'lxml')
    
    contentDomainSoup = domainSoup.find('div', id = 'row')
    contentDomainSoup2 = contentDomainSoup.find('tbody')
    contentDomainSoup3 = contentDomainSoup2.findAll('th', nowrap = "nowrap")

    contentSmtpSoup = smtpSoup.find('div', id = 'row')
    contentSmtpSoup2 = contentSmtpSoup.find('tbody')
    contentSmtpSoup3 = contentSmtpSoup2.findAll('th', nowrap = "nowrap")

    list = []

    for th in contentDomainSoup3:
        a = th.find('a').text
        list.append(a)

    for th in contentSmtpSoup3:
        b = th.find('a').text
        list.append(b)

    ciaTable = ciaTableProduction(impactListCIA)
    # Strings from protocols[ftp,SMTP,HTTP] CIA impact table
    confidentiality = ciaTable[0]
    integrity = ciaTable[1]
    availability = ciaTable[2]

    for cve in list:
        # URLs
        CVE = cve
        print("\n")
        print(CVE)
        nistUrl = 'https://nvd.nist.gov/vuln/detail/' + CVE   #the cve will produced by the cpe->cve process
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
        
        # TODO: Complete the control flow    
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
    except Exception as e:
        print(str(e))
    return round(securityScore, 1)
     
def ciaTableProduction(impactList):
    smtpTableRelay = ["", "", ""]
    smtpTableStrangePort = ["", "", ""]
    smtpTableEnum = ["", "", ""]
    smtpAttacks = ["", "", ""]
    if impactList[0] == 'N':
        smtpTableRelay[0] = 'N'
        smtpTableRelay[1] = 'N'
        smtpTableRelay[2] = 'N'
    elif impactList[0] == 'H':
        smtpTableRelay[0] = 'H'
        smtpTableRelay[1] = 'N'
        smtpTableRelay[2] = 'L'
    
    if impactList[1] == 'N':
        smtpTableStrangePort[0] = 'N'
        smtpTableStrangePort[1] = 'N'
        smtpTableStrangePort[2] = 'N'
    elif impactList[1] == 'H':
        smtpTableStrangePort[0] = 'N'
        smtpTableStrangePort[1] = 'H'
        smtpTableStrangePort[2] = 'H'
    elif impactList[1] == 'L':
        smtpTableStrangePort[0] = 'N'
        smtpTableStrangePort[1] = 'L'
        smtpTableStrangePort[2] = 'L'
        
    if impactList[2] == 'N':
        smtpTableEnum[0] = 'N'
        smtpTableEnum[1] = 'N'
        smtpTableEnum[2] = 'N'
    elif impactList[2] == 'L':
        smtpTableEnum[0] = 'L'
        smtpTableEnum[1] = 'N'
        smtpTableEnum[2] = 'N'
    
    print("\n")
    print(smtpTableRelay)
    print(smtpTableStrangePort)
    print(smtpTableEnum)
    smtpAttacks[0] = min(smtpTableRelay[0], smtpTableStrangePort[0], smtpTableEnum[0])
    smtpAttacks[1] = min(smtpTableRelay[1], smtpTableStrangePort[1], smtpTableEnum[1])
    smtpAttacks[2] = min(smtpTableRelay[2], smtpTableStrangePort[2], smtpTableEnum[2])
    print("\nCIA impact table: ")
    print(smtpAttacks)
    return smtpAttacks

def parseOutputTxt(dict1, dict2, dict3, fileNames):   
    # opening 3 text files
    file1 = open(fileNames[0], "r")
    file2 = open(fileNames[1], "r")
    file3 = open(fileNames[2], "r")
    # read each file's content
    readFile1 = file1.read()
    readFile2 = file2.read()
    readFile3 = file3.read()
    resultFile1 = ""
    resultFile2 = ""
    resultFile3 = ""
    try:
        for key1 in dict1.keys(): 
            if key1 in readFile1: 
                print('\nString', key1, 'found in file', fileNames[0])
                resultFile1 += dict1[key1]
            else: 
                print('\nString', key1 , 'not found in file', fileNames[0],'\n') 
                
        for key2 in dict2.keys(): 
            if key2 in readFile2: 
                print('\nString', key2, 'found in file', fileNames[1])
                resultFile2 += dict2[key2]
                if resultFile2 == 'H': break
            else: 
                print('\nString', key2 , 'not found in file', fileNames[1],'\n')
        #if keys not in dict get N
        if resultFile2 == "" : resultFile2 = 'N'

        for key3 in dict3.keys(): 
            if key3 in readFile3: 
                print('\nString', key3, 'found in file', fileNames[2])
                resultFile3 += dict3[key3]
            else: 
                print('\nString', key3 , 'not found in file', fileNames[2],'\n')
        if (resultFile3 == "LN" or resultFile3 == "LNN") : resultFile3 = "N"
        if (resultFile3 == "LL" or resultFile3 == "LNL" or resultFile3 == "NL") : resultFile3 = "L"
    except Exception as e:
        print(str(e))
    # closing the files
    file1.close()
    file2.close()
    file3.close() 
    resultProtocol = [resultFile1, resultFile2, resultFile3]
    return resultProtocol

if __name__ == "__main__":
    argumentList = sys.argv[1:]
    options = "s:f:t:a:h"
    long_options = ["smtp =", "ftp =", "http =", "all ="]
    dictSmtpOpenRelay = {"Server is an open relay" : "H", "Server doesn't seem to be an open relay" : "N"}
    dictSmtpStrangePort = {"unusual port: possible malware" : "H", "open  unknown" : "L"} 
    dictSmtpEnum = {"|_  " : "L", "Couldn't find" : "N", "unhandled status" : "L"} 
    dictFtpAnon = {"Anonymous FTP login allowed" : "H"}
    dictFtpBounce = {"bounce working!" : "H"}
    dictFtpBrute = {}
    dictHttp = {}
    try: 
        arguments, values = getopt.getopt(argumentList, options, long_options)
        
        for currentArgument, currentValue in arguments:
            try:
                if currentArgument in ("-s", "--smtp"):
                    smtpFileNames = ["openRelayOut.txt", "strangePortOut.txt", "enumOut.txt"]
                    print ("SMTP")
                    print (("IP is: % s") % (currentValue))
                    processSmtp = subprocess.Popen(["scriptSMTP.sh", currentValue], shell=True)
                    processSmtp.wait()
                    smtpImpactList = parseOutputTxt(dictSmtpOpenRelay, dictSmtpStrangePort, dictSmtpEnum, smtpFileNames)
                    securityScore = securityScoreCalc(smtpImpactList)
                    print("\nThe impact of the attacks in the smtp server is ")
                    print(smtpImpactList)
                    print("\nSmtp server security score is ")
                    print(securityScore)
                    if securityScore <= 0.2:
                        print("\nSecurity is strong")
                    elif securityScore <= 0.6:
                        print("\nSecurity is moderate")
                    else:
                        print("\nSecurity is weak")
                elif currentArgument in ("-f", "--ftp"):
                    ftpFileNames = ["anonOut.txt", "bounceOut.txt", "bruteOut.txt"]
                    print ("FTP")
                    print (("IP is: % s") % (currentValue))
                    processFtp = subprocess.Popen(["scriptFTP.sh", currentValue], shell=True)
                    processFtp.wait()
                    ftpImpactList = parseOutputTxt(dictFtpAnon, dictFtpBounce, dictFtpBrute, ftpFileNames)
                    print("\nThe impact of the attacks in the ftp server is ")
                    print(ftpImpactList)
                elif currentArgument in ("-t", "--http"):
                    print ("HTTP")    
                    print (("IP is: % s") % (currentValue))
                    processHttp = subprocess.Popen(["scriptHTTP.sh", currentValue], shell=True)
                    processHttp.wait()
                    httpImpactList = parseOutputTxt(dictHttp)
                    print(httpImpactList)
                elif currentArgument in ("-a", "--all"):
                    print ("ALL")  
                    print ("USE AT YOUR OWN RISK")                    
                    print (("IP is: % s") % (currentValue))
                    processSmtp = subprocess.Popen(["script.sh", currentValue], shell=True)
                    time.sleep(1)
                    processFtp = subprocess.Popen(["script.sh", currentValue], shell=True)
                    time.sleep(1)
                    processHttp = subprocess.Popen(["script.sh", currentValue], shell=True)
                    processSmtp.wait()
                    processFtp.wait()
                    processHttp.wait()
                elif currentArgument in ("-h", "--help"):
                    print ("HELP")  
            except Exception as e:
                print(str(e))
                sys.exit()
    except getopt.error as err:
        # output error, and return with an error code
        print (str(err))
        print("Type -h or --help for help")
        sys.exit()
    
    baseEnvScoreCalc(smtpImpactList) 
    
    
    