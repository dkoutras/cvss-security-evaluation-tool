#!/bin/bash

echo "information needed for base score production for FTP ... initializing"

rm serverInfo.txt
nmap -A -sV -T5 -p- --version-all "$1" >> serverInfo.txt

rm Ftp.txt
cat serverInfo.txt | grep 'open  ftp' | cut -d ' ' -f 8-12 --output-delimiter=+ >> Ftp.txt
echo "Information extracted for environmental score production ... loading"

rm firewallOut.txt
nmap -Pn --script firewall-bypass --script-args firewall-bypass.helper="ftp", firewall-bypass.targetport=21 "$1" >> firewallOut.txt
echo "firewall bypass vulnerability check"

#use the server info txt
echo "anon attack check"

rm bounceOut.txt
nmap -Pn --script ftp-bounce "$1" >> bounceOut.txt	
echo "bounce attack check"

sleep 1