#!/bin/bash

echo "information neededfor base score production ... initializing"

rm serverInfo.txt
nmap -A -sV -T5 -p- --version-all "$1" >> serverInfo.txt

rm Domain.txt
cat serverInfo.txt | grep 'open  domain' | cut -d ' ' -f 8-10  --output-delimiter=+ >> Domain.txt

rm Smtp.txt
cat serverInfo.txt | grep 'open  smtp' | cut -d ' ' -f 8 >> Smtp.txt
echo "Information extracted for environmental score production ... loading"

read -p "press d for default mode or w for wordlist mode(u have to put a wordilist) " mode

if [ $mode == 'w' ] ;
then
	echo "smtp wordlist mode"
	echo "Checking for enum-users"
	read -p "put the name of the username's worlist .txt file e.g <wordlist.txt> " username
	rm enumOut.txt
	nmap --script smtp-enum-users.nse --script-args userdb=$username -p 25,80,2525,8080 "$1" >> enumOut.txt
	echo "enum works"
	sleep 5
elif [ $mode == 'd' ] ;
then 
	echo "smtp default mode"
	echo "Checking for enum-users"
	rm enumOut.txt
	nmap --script smtp-enum-users.nse -p 25,80,2525,8080 "$1" >> enumOut.txt
	echo "enum works"
	sleep 5
else
	echo "sou eipa ti na grapseis"
	sleep 5
fi

rm strangePortOut.txt
nmap -sV -T5 -p- --script=smtp-strangeport "$1" >> strangePortOut.txt
./posrScan -ip "$1" >> strangePortOut.txt
#nmap -p- -T5 "$1" >> strangePortOut.txt
	
echo "strangePort works"	

rm openRelayOut.txt
nmap --script smtp-open-relay.nse -p 25,80,2525,8080 "$1" >> openRelayOut.txt
	
echo "openRelay"

sleep 10
