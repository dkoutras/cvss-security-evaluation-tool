#! /bin/bash

echo "information needed for base score production for HTTP ... initializing"

rm serverInfo3.txt
nmap -A -sV -T5 -p- --version-all "$1" >> serverInfo3.txt
# slow

rm Http.txt
cat serverInfo3.txt | grep 'open  http' | cut -d ' ' -f 11-13 --output-delimiter=+ >> Http.txt
echo "Information extracted for environmental score production ... loading"

rm refOut.txt
nmap -Pn -p80 --script http-referer-checker.nse "$1" >> refOut.txt
echo "Informs about cross-domain include of script"

rm sslOut.txt
nmap -Pn -sV -sC -p443 --script ssl-enum-ciphers "$1" >> sslOut.txt
echo "SSL/TLS version" 

rm certOut.txt
sslyze "$1" >> certOut.txt	
echo "Certificate chain"

sleep 1