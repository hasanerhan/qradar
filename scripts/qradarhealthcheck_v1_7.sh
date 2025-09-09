#!/usr/bin/env bash
## AUTHORS     : Hasan Erhan AYDINOGLU & Koray Mert ARAS
# EMAILS      : hasanerhan@hasanerhan.com || koray.mert.aras1@ibm.com
# START DATE  : 2024/02/26
# UPDATE DATE : 2025/05/24
# VERSION     : Check REV variable
# DESCRIPTION : This script working on Qradar to shorten the time of data collection for Health Check. 
# CHANGELOG   : v1.0 First Publication
#   v1.1 Fixes applied
#   v1.2 Output file information added
#        Scripts seperated and managed host' script run from console
#   v1.3 Added JMX properties
#        Fixes on producing logs
#        Added check for Qradar commands 
#        Added AQL searches                 
#   v1.4 Fix on structure
#   v1.5 Structure change
#   v1.6 Script must run from Screen || Tmux added
#		 @koray.mert.aras joined. 
#		 Ratio compression added to DSM Unrecognised/EventParsed 
#		 Wincollect Health Check eklendi
#  v.1.7
#TODO:
#  	202508-001:Add Log Analysis
# 	202508-002:More detailed analysis on tunnels
#  	202509-001:
# get service pid number
#systemctl show ecs-ec-ingress  --property MainPID --value
# then check pid pidstat -u 5 -p PID_NUMBER -h with some modification pidstat will be added
if [ -f /root/all.tar ] || [ -d /root/from* ] ||  [ -f /root/healthcheck.tar ] ||  [ -f /root/healthcheck.tar.gz ]
then 
	rm -rf /root/from* /root/all.tar /root/healthcheck.tar /root/healthcheck.tar.gz
fi
clear
##Base Variables
REV="1.7"
DEST="/root/HealthCheck"
MYH=$(hostname -s)
LOG=${DEST}/${MYH}_healthcheck.log
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color
$(which rm) -rf $DEST
$(which mkdir) -p $DEST
touch $LOG
##FirstCheck:Any store folder exist?
[ ! -d /store ] && { printf "${RED}Store${NC} partiton not found.\nThis server should be ${GREEN} Secondary${NC} or ${RED}QRadar not installed correctly.${NC}\nQuiting...\n" 2>&1 | tee -a $LOG; exit 17; } || echo "Store partion found we are continue" 2>&1 | tee -a $LOG
#Qradar Variables
RealIPConsole="$(/opt/qradar/bin/myver -cip)"
DefinedIPConsole="192.168.252.10"
#DefinedIPConsole="10.0.8.230" #GOC
#API_KEY="
#API_KEY="fa55f3ed-7c16-46d8-81e3-af10178cd04f" #GOC
API_VERSION="16.0"
CAPABILITIESFILE="/opt/qradar/conf/capabilities/hostcapabilities.xml"
APPLIANCETYPE="$(/opt/qradar/bin/myver -a)"
AMICONSOLE="$(/opt/qradar/bin/myver -c)"
if [ $AMICONSOLE == "true" ]
then
	if [[ "$TERM" =~ "screen" ]] || [[ "$TMUX" =~ "tmux" ]]
	then
		sleep 1
	else
		echo "Run the script from screen or tmux"
		exit 0
	fi
fi
# Get Console IP and API key from user
if [ $AMICONSOLE == "true" ]
then
	read -p "Enter the Console IP address: " DefinedIPConsole
	if [ -z "$DefinedIPConsole" ]; then
	  echo "No Console IP address entered. Exiting..."
	  exit 1
	fi

	read -p "Enter the API key: " API_KEY
	if [ -z "$API_KEY" ]; then
  		echo "No API key entered. Exiting..."
  	exit 1
	fi
fi
echo "$(date) $MYH started" 2>&1 | tee -a ${DEST}/westart >/dev/null
#PREDEFINED FUNCTIONS
function ct(){ #Testing Linux command 
    if [ ! -f $1 ]
    then
        echo "Command $1 not found existing " 2>&1 | tee -a $LOG
        exit 0
    fi
}
function qct(){ #Testing qradar command function
    if [ ! -f $1 ]
    then
        echo "Command/Path $1 not found"  2>&1 | tee -a $LOG
        echo "Shall we continue? (y/n)"
        read respn
        if [ $respn == "n" ]
        then
            echo "We are exiting because QRadar Command/Path $1 not found..."
            exit 0
        else
            echo "$1 not found but we are processing"  2>&1 | tee -a $LOG
        fi
    fi
}
#Linux Commands
DD=$(which dd) && ct "$DD"
DU=$(which du) && ct $DU
SYSCTL=$(which systemctl) && ct $SYSCTL
FIND=$(which find) && ct $FIND
MKDIR=$(which mkdir) && ct $MKDIR
RM=$(which rm) && ct $RM
EXP=$(which expect) && ct $EXP
CP=$(which cp) && ct $CP
MV=$(which mv) && ct $MV 
SSH=$(which ssh) && ct $SSH
DMESG=$(which dmesg) && ct $DMESG
FIO=$(which fio) && ct $FIO
LSBLK=$(which lsblk) && ct $LSBLK
BLK=$(which blkid) && ct $BLK
IOSTAT=$(which iostat) && ct $IOSTAT
DF=$(which df) && ct $DF
LSCPU=$(which lscpu) && ct $LSCPU
UPT=$(which uptime) && ct $UPT
VMS=$(which vmstat) && ct $VMS
HNAME=$(which hostnamectl) && ct $HNAME
HSTN=$(which hostname) && ct $HSTN
IPC=$(which ip) && ct $IPC
TOP=$(which top) && ct $TOP
XFS=$(which xfs_info) && ct $XFS
IOT=$(which iotop) && ct $IOT
JQ=$(which jq) && ct $JQ
IFC=$(which ifconfig) && ct $IFC
CURL=$(which curl) && ct $CURL
DMI=$(which dmidecode) && ct $DMI
JCTL=$(which journalctl) && ct $JCTL
ETHTOOL=$(which ethtool) && ct $ETHTOOL
TRUNCATE=$(which truncate) && ct $TRUNCATE
SAR=$(which sar) && ct $SAR
DRBDO=$(which drbd-overview) && ct $DRBDO
TDUMP=$(which tcpdump) && ct $TDUMP
ISTMUXEXIST=$(hash tmux 2>/dev/null;echo $?)
#Which one is installed Screen or Tmux?
SCRIPT=$(echo $0 | awk -F\/ '{print $NF}')
# Test QRadar Commands
[ -f /etc/management_interface ] && MGMTINT="$(cat /etc/management_interface)" || qct /etc/management_interface
[ -f /opt/qradar/support/all_servers.sh ] && ALLS="/opt/qradar/support/all_servers.sh" || qct /opt/qradar/support/all_servers.sh
[ -f /opt/qradar/bin/myver ] && MYVER="/opt/qradar/bin/myver" || qct /opt/qradar/bin/myver
[ -f /opt/qradar/support/deployment_info.sh ] && DEPINFO="/opt/qradar/support/deployment_info.sh" || qct /opt/qradar/support/deployment_info.sh
[ -f /opt/qradar/support/validate_deployment.sh ] && VALDEP="/opt/qradar/support/validate_deployment.sh" || qct /opt/qradar/support/validate_deployment.sh
[ -f /opt/qradar/upgrade/util/setup/upgrades/wait_for_start.sh ] && WFS="/opt/qradar/upgrade/util/setup/upgrades/wait_for_start.sh" || qct /opt/qradar/upgrade/util/setup/upgrades/wait_for_start.sh
[ -f /opt/qradar/support/jmx.sh ] && JMX="/opt/qradar/support/jmx.sh" || qct /opt/qradar/support/jmx.sh
[ -f /opt/qradar/support/WinCollectHealthCheck.sh ] && WINCOLCHK="/opt/qradar/support/WinCollectHealthCheck.sh" || qct /opt/qradar/support/WinCollectHealthCheck.sh
[ -f /opt/qradar/support/defect-inspector ] && DEFINSP="/opt/qradar/support/defect-inspector" || qct /opt/qradar/support/defect-inspector
[ -f /opt/qradar/support/get_cert_info.sh ] && GETCERT="/opt/qradar/support/get_cert_info.sh" || qct /opt/qradar/support/get_cert_info.sh
[ -f /opt/qradar/support/collectGvStats.sh ] && GVSTAT="/opt/qradar/support/collectGvStats.sh" || qct /opt/qradar/support/collectGvStats.sh
NTTUNE=$(find /opt/qradar -type f -iname qradar_nettune.pl  |tail -1)

#MAIN FUNCTIONS
#FUNCTIONS START
function version { #script version 
 clear
 echo -e "\tVERSION:$SCRIPT $REV"
 echo -e "\tAUTHORS: Hasan Erhan AYDINOGLU & Koray Mert ARAS"
 echo -e "\tEMAILS : hasanerhan@hasanerhan.com || koray.mert.aras1@ibm.com"
}
function usage { #Own script usage Function
 clear
 version
 echo "Usage: Run script on console first"
 echo -e "\t-v :: Script Version"
 echo -e "\t-h :: Help (This information)"
 echo -e "\n"
}
function title { #Title for reports
  clear
  echo -e "\n: $1 " | tee -a $LOG >> /dev/tty
}
function subtitle { #Subtitle for reports
 echo -e ":: $1 " | tee -a $LOG >> /dev/tty
}
function info { #Info under subtitle for reports
echo -e "::: $1 " | tee -a $LOG >> /dev/tty
sleep 1
}
function decidingrole {
	if  [ "$APPLIANCETYPE" == "software" ]
	then
	mhrole=(
		"eventcollector:102"
		"eventprocessor:103"
		"flowprocessor:104"
		"flowcollector:101"
		"eventandflowprocessor:105"
		"datanode:106"
		"vulnerabilityprocessor:107"
		"vulnerabilityscanner:108"
		"riskmanager:109"
		)
		SOFTWARETYPE=$(grep --text "softwareType" $CAPABILITIESFILE | awk -F"=" '{print $2}'| sed 's/"//g')
		for entry in "${mhrole[@]}"
		do
    		IFS=':' read -r role roleid <<< "$entry"
    		if [[ $roleid -eq $SOFTWARETYPE ]]; then
        		MYROLE="$role" 
				echo "I have $MYROLE role" | tee -a $LOG >> /dev/tty
        	fi	
        done
	else
		echo "This is not software installation continue to check"
		HARDWARETYPE=$(grep --text "applianceType" $CAPABILITIESFILE | awk -F"=" '{print $2}'| sed 's/"//g' | sed  's/\([0-9][0-9]\)[0-9][0-9]/\1xx/g')
		mhrole=( 
		"eventcollector:15xx" 
		"eventprocessor:16xx" 
		"flowprocessor:17xx" 
		"flowcollector:11xx" 
		"flowcollector:12xx" 
		"flowcollector:13xx" 
		"eventandflowprocessor:18xx"
		"datanode:14xx"
		"console:21xx" 
		)
	 	for entry in "${mhrole[@]}"
        do
        	IFS=':' read -r role roleid <<< "$entry"
            if [[ "$roleid" ==  "$HARDWARETYPE" ]] 
            then
				MYROLE="$role"
                echo "My role is $MYROLE in deployment" | tee -a $LOG >> /dev/tty
            fi
        done
	fi
}
function deploymentmodel {
	mhcountx=$(psql -U qradar --no-align -q -t -0 -c "select count(hostname) from managedhost where isconsole <> 't' and appliancetype <> '4000';")
	if [ $mhcountx -gt 0 ]
	then
		DEPLOYMENTIS="distributed" 
	else
		DEPLOYMENTIS="aio"
		MHGROUPREGEX="ALL"
	fi
}
function scriptrunon {
	if [ "$DEPLOYMENTIS" == "distributed" ]
	then
		clear
		printf "This is ${GREEN}"distributed"${NC} deployment. There are ${GREEN}${mhcountx}${NC} MH(s).\nAll MH(s) on deployment listed below\n" 2>&1 | tee -a $LOG 
		echo "$(psql -U qradar -t -c "select hostname from managedhost where isconsole <> 't' and  status='Active' and appliancetype <> '4000';")" 2>&1 | tee -a $LOG
		printf "You can type ${GREEN}"ALL"${NC} to run the script in the entire environment\n" 
		printf "You can ${GREEN}copy and paste a server name${NC} listed above to run script on the selected server\n"
		printf "You can type ${GREEN}part of the server name${NC} listed above to run the script on the server(s) which regex match\n"  
		read MHGROUPREGEX
		echo "$MHGROUPREGEX choosen for MH(s)" 2>&1 | tee -a $LOG
		clear
		if [ $MHGROUPREGEX == "ALL" ]
		then
			echo "You choose to run on ALL Deployment"
		else
			echo -e "You choose to run on \n$(psql  -U qradar -q -t -c "select hostname from managedhost where isconsole <> 't' and status='Active' and  appliancetype <> '4000' and hostname ilike '%${MHGROUPREGEX}%';")"
		fi
	else
		clear
		printf "This is ${GREEN}"AIO"${NC} deployment" 2>&1 | tee -a $LOG
		sleep 5
	fi
}
function findmymhlist {
if [ "$DEPLOYMENTIS" == "distributed" ] 
then
#How Many MH(s) we have
	if [ "$MHGROUPREGEX" == "ALL" ]
	then
		mhcountx=$(psql -U qradar --no-align -q -t -0 -c "select count(ip) from managedhost where isconsole <> 't' and status='Active' and appliancetype <> '4000';")
	else
		mhcountx=$(psql -U qradar --no-align -q -t -0  -c "select count(ip) from managedhost where isconsole <> 't' and status='Active' and appliancetype <> '4000' and hostname like '%${MHGROUPREGEX}%';")
	fi
	echo "Getting MHs IP addresses you typed"  2>&1 | tee -a $LOG
	#What is IP addresses of selected MH(s)
	#HEA:Removed declare -a MyMHs
	if [ $MHGROUPREGEX == "ALL" ]
	then
		for mh in $(psql -U qradar -t -c "select ip from managedhost where isconsole <> 't' and  status='Active' and appliancetype <> '4000';")
		do
			MyMHs+=($mh)
        done
    else
    		for mh in $(psql  -U qradar -q -t -c "select ip from managedhost where isconsole <> 't' and  status='Active' and appliancetype <> '4000' and hostname ilike '%${MHGROUPREGEX}%';")
			do
				MyMHs+=($mh)
			done
    
	fi
	#SSH Connect Test to selected MH(s) and decide last array of MH(s)
	for mh in ${MyMHs[@]};
	do
		$SSH $mh -o ConnectTimeout=3 -x "echo"  >/dev/null
		if [ $? -ne 0 ];
		then
			echo "IP address of MHs is $mh but SSH is not successfull for mh. We are deleting from array : $mh" 2>&1 | tee -a $LOG
			MyMHs=("${MyMHs[@]/$mh}")
		else
			sleep 1
			echo "IP address of MHs is $mh and we can SSH." 2>&1 | tee -a $LOG
		fi
	done
fi
}
function testingipandapikey {

	[ -z $DefinedIPConsole ] &&  { echo -e "Console IP adress not defined. Quiting..." ; exit 17; }
	[ -z $API_KEY ] && { echo -e "Console API_KEY not defined. Quiting..." ; exit 17; }
	[ $RealIPConsole != $DefinedIPConsole ] && { echo "Defined IP is different than console's IP address. Quiting..."; exit 17; }
	if [ $AMICONSOLE == "true" ]
	then
	$CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20*%20from%20events%20limit%201%20last%201%20MINUTES" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" | grep search_id 2>&1 >/dev/null
 		if [ $? -eq 0 ] 
 		   	then
    		echo
    	else
    		 echo -e "Defined API_KEY is not getting any value from console. May be wrong. Quiting...\n" 
    		 exit 17
    	fi
    	
	fi
}
function hashcollect {
	if [ "$DEPLOYMENTIS" == "distributed" ]
	then
		if [ $MHGROUPREGEX == "ALL" ]
		then
			echo "Checking hash for deployment.xml file, output at ${DEST}/${MYH}_hash_output.log" 2>&1 | tee -a $LOG
			$ALLS -t 1 -C "md5sum /opt/qradar/conf/deployment.xml"  2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			echo "Checking hash for nva.conf file " 2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			$ALLS -t 1 -C "md5sum /opt/qradar/conf/nva.conf"  2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			echo "Checking hash for arielConfig.xml file" 2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			$ALLS -t 1 -C "md5sum /opt/qradar/conf/arielConfig.xml" 2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			echo "Checking hash for login.conf file" 2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			$ALLS -t 1 -C "md5sum /store/configservices/staging/globalconfig/login.conf" 2>&1 | tee -a ${DEST}/${MYH}_hash_output.log > /dev/null 
			echo "Checking syslog-tls certificates files validty" 2>&1 | tee -a $LOG
			$ALLS -t 1 -C "openssl x509 -enddate -in /opt/qradar/conf/trusted_certificates/syslog-tls.cert -noout" 2>&1 | tee -a $LOG > /dev/null 
		else 
			echo "Checking hash for deployment.xml file" 2>&1 | tee -a $LOG
			$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "md5sum /opt/qradar/conf/deployment.xml"  2>&1 | tee -a $LOG > /dev/null 
			echo "Checking hash for nva.conf file" 2>&1 | tee -a $LOG
			$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "md5sum /opt/qradar/conf/nva.conf"  2>&1 | tee -a $LOG > /dev/null 
			echo "Checking hash for arielConfig.xml file" 2>&1 | tee -a $LOG
			$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "md5sum /opt/qradar/conf/arielConfig.xml" 2>&1 | tee -a $LOG > /dev/null 
			echo "Checking hash for login.conf file" 2>&1 | tee -a $LOG
			$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "md5sum /store/configservices/staging/globalconfig/login.conf" 2>&1 | tee -a $LOG > /dev/null 
			echo "Checking syslog-tls certificates files validty" 2>&1 | tee -a $LOG
			$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "openssl x509 -enddate -in /opt/qradar/conf/trusted_certificates/syslog-tls.cert -noout" 2>&1 | tee -a $LOG > /dev/null
		fi
		#Check all nva.conf and all deployment.xml file
		echo "Checking hash for deployment.xml file inside console" 2>&1 | tee -a $LOG
		find /store/configservices/ /opt/ -iname deployment.xml -exec md5sum {} \; | sort 2>&1 | tee -a $LOG > /dev/null 
		echo "Checking hash for nva.conf file inside console" 2>&1 | tee -a $LOG
		find /store/configservices/ /opt/ -iname nva.conf -exec md5sum {} \; | sort | sort 2>&1 | tee -a $LOG > /dev/null 
	else
		#Check all nva.conf and all deployment.xml file
		echo "This is AIO so we checking backup and existing files hash values" 2>&1 | tee -a $LOG
		echo "Checking hash for deployment.xml file" 2>&1 | tee -a $LOG
		find /store/configservices/ /opt/ -iname deployment.xml -exec md5sum {} \; | sort 2>&1 | tee -a $LOG > /dev/null 
		echo "Checking hash for nva.conf file" 2>&1 | tee -a $LOG
		find /store/configservices/ /opt/ -iname nva.conf -exec md5sum {} \; | sort | sort 2>&1 | tee -a $LOG > /dev/null 
	fi
}
function hosttokens {
	subtitle "Decrypt all host tokens for MH(s) defined in console"
	declare -a hosttokens
	for i in $(cat /opt/qradar/conf/host_tokens.masterlist  | tail -n+2 |sed 's/=/ /g' | sed -e 's/\\ \\//'|awk {'print $1 ":" $2'})
	do
		hosttokens+=($(echo $i))
	done
	for ht in "${hosttokens[@]}"
    do
        IFS=':' read -r HOST TOKEN <<< "$ht"
        echo "$HOST : $(echo $TOKEN|java -jar /opt/qradar/jars/ibm-si-mks.jar decrypt_command_line)"  2>&1 | tee -a $LOG > /dev/null 
	done
}
#CURL PART
function notificationviewstatus {
	declare -a MYNOTVW
    MYNOTVW=($(for i in $(psql -t -U qradar -c "select distinct(qid)from notification_view limit 20;"); do echo $i;sleep 1 ;done))
    for mynotvw in ${MYNOTVW[@]}
    do
    nview=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D${mynotvw}%20order%20by%20starttime%20desc%20LIMIT%205%20last%202%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
        while [ true ]
    do    	
    	nvstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${nview}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "${nvstatus}" == "COMPLETED" ]
    	then
    		 echo -ne "\tNotification Search for $mynotvw now $nvstatus                  \r" 2>&1 | tee -a $LOG 
    		break
    	else
    		 echo -ne "\tNotification Search for $mynotvw status still $nvstatus         \r" 2>&1 | tee -a $LOG 

    	fi
    	sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${nview}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
	done
}
function epsratesperlsstatus {
	epsratels=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20logsourceid%2c%20logsourcename%28logsourceid%29%20as%20%22LogSource%22,%20long%28SUM%28eventcount%29%29/3600%20AS%20%22EPS%22%20from%20events%20group%20by%20LogSource%20order%20by%20EPS%20desc%20LIMIT%2010%20last%2060%20MINUTES" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    while [ true ]
    do
    	erlsstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${epsratels}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        if [ "$erlsstatus" == "COMPLETED" ]
        then
        	echo -ne "\tEPS per LogSource Search now $erlsstatus          \r"
        	break
        else
        	echo -ne "\tEPS per LogSource Search status still $erlsstatus \r"
        fi
        sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${epsratels}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a ${DEST}/logsourceinfo.log > /dev/null
	
}
function localiplistlistedotherinnh {
    nhlist=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20sourceip%2cNETWORKNAME%28sourceip%29%20from%20events%20where%20%28%20INCIDR%28'10.0.0.0/8'%2c%20sourceip%29%20or%20INCIDR%28'192.168.0.0/16'%2c%20sourceip%29%20or%20INCIDR%28'172.16.0.0/20'%2c%20sourceip%29%29%20and%20NETWORKNAME%28sourceip%29%20%3D%20'other'%20%20group%20by%20sourceip%20order%20by%20sourceip%20LIMIT%2020%20last%2030%20MINUTES" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    while [ true ]
    do
    	nhliststatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${nhlist}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "$nhliststatus" == "COMPLETED" ]
    	then
	    	echo -ne "\tEPS per LogSource Search now $nhliststatus         \r"
    		break
    	else
			echo -ne "\tNetwork Hierarchy Search status still $nhliststatus\r"
    	fi
    	sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${nhlist}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null 
}
function failedtoreadrule {
	crefailedrules=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750107%20LIMIT%2010%20last%205%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    while [ true ]
    do
    	frstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${crefailedrules}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "$frstatus" == "COMPLETED" ]
    	then
    	    echo -ne "\tCRE: Failed to read rules Search now $frstatus          \r"
			break
		else
			echo -ne "\tCRE: Failed to read rules Search status still $frstatus \r"
    	fi
    	sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${crefailedrules}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
}
function expensivecustomrule {
	expensiverules=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750120%20LIMIT%2010%20last%205%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
	while [ true ]
    do
    	erstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${expensiverules}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "$erstatus" == "COMPLETED" ]
    	then
    		echo -ne "\tExpensive Custom Rules Search now $erstatus         \r"
    		break
    	else
    		echo -ne "\tExpensive Custom Rules Search status still $erstatus \r"
    	fi
    	sleep 5

    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${expensiverules}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
}
function expensivecustomproperties {
   	expensiveproperties=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750138%20or%20qid%3D38750097%20LIMIT%2010%20last%205%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    while [ true ]
    do
    	eprostatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${expensiveproperties}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "$eprostatus" == "COMPLETED" ]
    	then
			echo -ne "\tExpensive Custom Properties Search now $eprostatus          \r"
    		break
    	else
			echo -ne "\tExpensive Custom Properties Search status still $eprostatus \r"

    	fi
		sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${expensiveproperties}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
}
function copyandrun {
if [ "$DEPLOYMENTIS" == "distributed" ]
then
 	echo "To parallel running, we are copying script to all || selected MH(s)" 2>&1 | tee -a $LOG 
 	if [ $MHGROUPREGEX == "ALL" ] #ON ALL SERVER
 	then
 		clear
 		echo "We are copying on to $mhcountx server"
 		$ALLS -t 1 -p /root/$SCRIPT -r /root 
 	 	sleep 5
 	 	if [ $ISTMUXEXIST -eq 0 ] #Check TMUX or SCREEN
 	 	then
 	 		$ALLS -t 1 "$(which tmux) new -s ELHC -d 'bash /root/${SCRIPT} \r'"  >/dev/null
 	 	else #NOT TMUX BUT SCREEN
 	 		$ALLS -t 1 "$(which screen) -S ELHC -dm"   >/dev/null
	      	$ALLS -t 1 "$(which screen) -S ELHC -X stuff 'bash /root/${SCRIPT};exit\r'" >/dev/null
 	 	fi
 	 else #ON PARTIAL SERVER
		echo "We are copying on to selected server"
		$ALLS -t 1 -n "%${MHGROUPREGEX}%" -p /root/$SCRIPT -r /root
 	  	if [ $ISTMUXEXIST -eq 0 ] #Check TMUX or SCREEN
 	 	then
 	 		$ALLS -t 1 -n "%${MHGROUPREGEX}%" "$(which tmux) new -s ELHC -d 'bash /root/${SCRIPT} \r'"  >/dev/null  	
 	 	else #NOT TMUX BUT SCREEN
 	 		$ALLS -t 1 -n "%${MHGROUPREGEX}%" "$(which screen) -S ELHC -dm"   >/dev/null
	      	$ALLS -t 1 -n "%${MHGROUPREGEX}%" "$(which screen) -S ELHC -X stuff 'bash /root/${SCRIPT};exit\r'"   >/dev/null
	    fi
	fi
	clear
	echo "We already started the script on selected MH(s) server. We are continuing on console."
	sleep 3
	clear

fi
}
function generalenvironmentalinfo {
	 if [ $MHGROUPREGEX == "ALL" ] || [ $DEPLOYMENTIS == "aio" ] #ON ALL SERVER
	 then
	 	echo "***************"  2>&1 | tee -a $LOG > /dev/null
	 	echo "***************"  2>&1 | tee -a $LOG > /dev/null
	 	echo ""
	 	info "Getting CPU Models from MH(s)" 
	 	$ALLS  -t 1 -C "cat /proc/cpuinfo | grep model | grep name |tail -1" 2>&1 | tee -a $LOG > /dev/null
	 	info "How Many CPU MH(s) have?"
	 	$ALLS -t 1 -C "cat /proc/cpuinfo |grep model | grep name | wc -l"  2>&1 | tee -a $LOG > /dev/null
	 	info "Getting Memory installed on MH(s)"
		$ALLS -t 1 -C "free -m | grep '^Mem: ' | tr -s ' '| cut '-d ' -f2" 2>&1 | tee -a $LOG > /dev/null
		info "Getting Hardware Class from MH(s) to understand capabilities"
		$ALLS -t 1 -C  "$MYVER -hwc" 2>&1 | tee -a $LOG > /dev/null 
		info "Getting Appliance Type from MH(s)"
		$ALLS -t 1 -C "$MYVER -a" 2>&1 | tee -a $LOG > /dev/null
		info "Getting Management Interfaces from MH(s)"
		$ALLS -t 1 -C "cat /etc/management_interface" 2>&1 | tee -a $LOG > /dev/null
		info "Getting IP addresses from MH(s)"
		$ALLS -t 1 -C "ip address show dev $MGMTINT | grep inet | grep $MGMTINT" 	2>&1 | tee -a $LOG > /dev/null
	else
		info "Getting CPU Models from MH(s)" 
		$ALLS  -t 1 -n "%${MHGROUPREGEX}%" -C "cat /proc/cpuinfo | grep model | grep name |tail -1" 2>&1 | tee -a $LOG > /dev/null
	 	info "How Many CPU MH(s) have?"
	 	$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "cat /proc/cpuinfo |grep model | grep name | wc -l"  2>&1 | tee -a $LOG > /dev/null
	 	info "Getting Memory installed on MH(s)"
		$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "free -m | grep '^Mem: ' | tr -s ' '| cut '-d ' -f2" 2>&1 | tee -a $LOG > /dev/null
		info "Getting Hardware Class from MH(s) to understand capabilities"
		$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C  "$MYVER -hwc" 2>&1 | tee -a $LOG > /dev/null 
		info "Getting Appliance Type from MH(s)"
		$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "$MYVER -a" 2>&1 | tee -a $LOG > /dev/null
		info "Getting Management Interfaces from MH(s)"
		$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "cat /etc/management_interface" 2>&1 | tee -a $LOG > /dev/null
		info "Getting IP addresses from MH(s)"
		$ALLS -t 1 -n "%${MHGROUPREGEX}%" -C "ip address show dev $MGMTINT | grep inet | grep $MGMTINT" 	2>&1 | tee -a $LOG > /dev/null
	 fi
}
function controlrunningscriptonmhs {
runonservercount=0
if [ "$DEPLOYMENTIS" == "distributed" ] && [ $AMICONSOLE == "true" ] 
then
 	
 	if [ $MHGROUPREGEX == "ALL" ] #ON ALL SERVER
	then
	   	while [ $runonservercount -lt $mhcountx ]
			do
				clear
				runonservercount=$($ALLS -t 1 "[ -f /root/healthcheck.tar.gz ] && echo yes || echo no" | grep yes | wc -l)
				if [ $runonservercount -lt $mhcountx ]
				then
					echo -ne "${runonservercount} of ${mhcountx} MH(s) finished to run the script. Listed below\r"
					$ALLS -t 1 "[ -f /root/healthcheck.tar.gz ] && echo done || echo still_running"
				else
					clear
					echo -e "\nAll Server finished to run script"
					wedoneatall="yes"
					break
				fi
			sleep 5
			done
			echo ""
	else 
		while [ $runonservercount -lt $mhcountx ]
			do
				runonservercount=$($ALLS -n "%${MHGROUPREGEX}%" -t 1 "[ -f /root/healthcheck.tar.gz ] && echo yes || echo no" | grep yes | wc -l)
				if [ $runonservercount -lt $mhcountx ]
				then
					echo -ne "${runonservercount} of ${mhcountx} MH(s) finished to run the script. Listed below\r"
					$ALLS -t 1 -n "%${MHGROUPREGEX}%" "[ -f /root/healthcheck.tar.gz ] && echo done || echo still_running"
				else
					clear
					echo  -e "\nAll Server finished to run script"
					wedoneatall="yes"
					break
				fi
			sleep 5
			done
			echo ""
	fi
fi
}
function dsm_unrecognized_rate_check {
    local PORT=7777
    local DOMAIN="com.q1labs.sem"
    local THRESHOLD=5
    local OUTFILE="${DEST}/${MYH}_dsm_unrecognized_rate_check.json"
    subtitle "DSM Unrecognized Event Rate Check" >> "$OUTFILE"
    echo "Running DSM Unrecognized Event Rate Check (threshold: ${THRESHOLD}%)" >> "$OUTFILE"
    $JMX -p $PORT -d "$DOMAIN" --json | $JQ -r --argjson threshold "$THRESHOLD" '
      .mbean
      | to_entries[]
      | select(
          (.key | test("application=ecs-ec\\.ecs-ec,type=filters,name=DSM,id=")) or
          (.key | test("name=DSM Extension"))
        )
      | {
          name: .key,
          EventsReceived: ((.value.attributes.EventsReceived | tonumber?) // 0),
          EventsUnrecognized: ((.value.attributes.EventsUnrecognized | tonumber?) // 0)
        }
      | select(.EventsReceived > 0)
      | . + {rate: ((.EventsUnrecognized / .EventsReceived) * 100)}
      | select(.rate > $threshold)
      | "\(.name)\n\tEventsReceived: \(.EventsReceived)\n\tEventsUnrecognized: \(.EventsUnrecognized)\n\tUnrecognizedRate: \(.rate | tostring)%\n"
    ' >> "$OUTFILE"
}
function check_qradar_eos() {
	local OUTFILE="${DEST}/${MYH}_check_eos_date.output"
    get_eos_info() {
        local hw_class="$1"
        case "$hw_class" in
            "xx05") echo "4379-Q05:30 September 2019" ;;
            "xx24") echo "4379-Q24:31 July 2020" ;;
            "21xx") echo "4378-Q21:30 September 2019" ;;
            "1201") echo "4378-QC1:30 September 2019" ;;
            "1202") echo "4378-QC2:30 September 2019" ;;
            "1301") echo "4378-QD1:30 September 2019" ;;
            "1310-SR") echo "4378-QSR:30 September 2019" ;;
            "1310-LR") echo "4378-QLR:30 September 2019" ;;
            "1501") echo "4378-Q21:30 September 2019" ;;
            "xx28") echo "4531-G1E:31 December 2021" ;;
            "xx28-G2") echo "4380-Q2E:31 December 2021" ;;
            "xx28-C") echo "4380-Q1F:30 September 2028" ;;
            "xx28-C-IF") echo "4531-G1F:28 June 2024" ;;
            "xx05-G2") echo "4380-Q1E:31 December 2021" ;;
            "xx05-G2-FF") echo "4380-Q2C:31 December 2021" ;;
            "xx05-G3") echo "4412-Q1E:31 December 2025" ;;
            "xx05-G4") echo "4563-Q3E:30 September 2028" ;;
            "xx48") echo "4412-Q3B:31 December 2025" ;;
            "xx48-G2") echo "4563-Q5B:30 September 2028" ;;
            "xx48-C") echo "4654-Q4B:30 September 2029" ;;
            "xx29") echo "4412-Q2A:31 December 2025" ;;
            "xx29-G2") echo "4563-Q4A:30 September 2028" ;;
            "xx29-C") echo "4654-Q3A:30 September 2029" ;;
            "1201-G2") echo "4380-Q2C:31 December 2021" ;;
            "1201-G4") echo "4563-Q5D:30 September 2028" ;;
            "1201-C") echo "4380-Q1G:28 June 2024" ;;
            "1202-G2") echo "4380-Q3C:31 December 2021" ;;
            "1202-C") echo "4380-Q1G:28 June 2024" ;;
            "1301-G2") echo "4380-Q4C:31 December 2021" ;;
            "1301-G4") echo "4563-Q5D:30 September 2028" ;;
            "1301-C") echo "4380-Q1G:28 June 2024" ;;
            "1310-SR-G2") echo "4380-Q5C:31 December 2021" ;;
            "1310-LR-G2") echo "4380-Q6C:31 December 2021" ;;
            "1310-SR-C") echo "4380-Q2G:28 June 2024" ;;
            "1310-LR-C") echo "4380-Q2G:28 June 2024" ;;
            "1310-SR/LR-C") echo "4654-Q3D:30 September 2029" ;;
            "1310") echo "4563-Q2G:30 September 2028" ;;
            "1501-G2") echo "4380-Q2C:31 December 2021" ;;
            "1501-G3") echo "4412-Q4D:30 April 2025" ;;
            "1501-G4") echo "4563-Q5D:30 September 2028" ;;
            "1901") echo "4412-F4Y:31 December 2025" ;;
            "1901-G2") echo "4563-F8Y:30 September 2028" ;;
            "1901-C") echo "4654-F6Y:30 September 2029" ;;
            "1910") echo "4412-F5Y:30 September 2025" ;;
            "1910-G2") echo "4563-F7Y:30 September 2028" ;;
            "1910-C") echo "4654-Q9C:30 September 2029" ;;
            "1920") echo "4412-F3F:31 December 2025" ;;
            "1920-G2") echo "4563-F5F:30 September 2028" ;;
            "1920-C") echo "4654-F4F:30 September 2029" ;;
            "1940") echo "4563-F6G:30 September 2028" ;;
            "1940-C") echo "4654-F7G:30 September 2029" ;;
            "low-end") echo "UNKNOWN:Unknown" ;;
            *) echo "" ;;
        esac
    }

	function is_expired() {
	    local eos="$1"
	    [[ -z "$eos" || "$eos" == "Unknown" ]] && return 1
	    [[ $(date +%s) -gt $(date -d "$eos" +%s 2>/dev/null) ]] && return 0 || return 1
	}

	function is_warning() {
	    local eos="$1"
	    [[ -z "$eos" || "$eos" == "Unknown" ]] && return 1
	    local warn=$(date -d "$eos -6 months" +%s 2>/dev/null)
	    [[ $(date +%s) -ge $warn ]] && return 0 || return 1
	}

	function get_status() {
	    local eos="$1"
	    if [[ "$eos" == "Unknown" ]]; then
	        echo "UNKNOWN"
	    elif is_expired "$eos"; then
	        echo "EXPIRED"
	    elif is_warning "$eos"; then
	        echo "WARNING"
	    else
	        echo "HEALTHY"
	    fi
	}

	function perform_check() {
	    local input="$1"
	    while read -r line; do
	        [[ $line =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]] || continue
	        ip=$(echo "$line" | awk '{print $1}')
	        host=$(echo "$line" | awk -F' - ' '{print $2}' | awk '{print $1}')
	        hw=$(echo "$line" | awk '{print $NF}')
	        
	        eos_info=$(get_eos_info "$hw")
	        model=$(echo "$eos_info" | cut -d: -f1)
	        eos_date=$(echo "$eos_info" | cut -d: -f2)

	        echo "[$ip] $host"
	        echo "	 HW Class: $hw"
	        echo "	 Model: $model"
	        echo "   EOS: $eos_date"
	        echo "   Status: $(get_status "$eos_date")"
	        echo ""
	    done <<< "$input"
	}

	{
	    echo "--- QRadar Hardware EOS Check ---"
	    hw_data=$($ALLS -t 1 -C "$MYVER -hwc")
	    [[ $? -ne 0 ]] && echo "Error: Failed to get hardware info." && exit 1
	    perform_check "$hw_data"
	} >> "$OUTFILE" 2>&1
}
#FUNCTIONS END
#PRE CHECKS MAIN SCRIPT START
[ $AMICONSOLE == "true" ] && title "PRE CHECKS on CONSOLE"
[ $AMICONSOLE == "true" ] && testingipandapikey #Is IP address defined is same with console?
[ $AMICONSOLE == "true" ] && MYROLE="console" #Am I console?
[ $AMICONSOLE == "false" ] && decidingrole  #What is my role if not console?
[ $AMICONSOLE == "true" ] && deploymentmodel #Is deploymet distributed or AIO?
[ $AMICONSOLE == "true" ] && scriptrunon #Select MH to copy and run script in distributed environment
[ $AMICONSOLE == "true" ] && copyandrun #Copy and run script on selected MH(s)
[ $AMICONSOLE == "true" ] && generalenvironmentalinfo #Gett genelral environmental infrmation from MH(s) - Run on only console
#In which MH(s) script run (Run Part)?
	[ $AMICONSOLE == "true" ] && findmymhlist
title "PRE CHECKS on ALL DEPLOYMENT"
#First is Store LVM or Partition **ISSTORELVM**
#
subtitle "Checking Store Partition is it LVM or not?"
	lvs --noheadings -o lv_all --reportformat json 2>/dev/null | jq -r '.report[].lv[] | select(.lv_name == "store") | .lv_path' | grep store 2>&1 >/dev/null
	[ $? -eq 0 ] && ISSTORELVM="true" || ISSTORELVM="false"
	#
	if [ $ISSTORELVM == "true" ]
	then
		info ":Store configured with lvm"
		GETVOLUME="$(lvs --noheadings -o lv_all --reportformat json 2>/dev/null | jq -r '.report[].lv[] | select(.lv_name == "store") | .lv_path' | grep store)"
		STOREINDMNAMING="$(for i in $(ls /dev/dm*); do dmsetup info $i | grep storerhel-store > /dev/null; [ $? -eq 0 ] && echo $i| tail -1  ;done)"
		info "Checking XFS for store partition - ${GREEN}LVM${NC}"
		$XFS $GETVOLUME 2>&1 | tee -a $LOG  > /dev/null
	else	
		info  ":Store is not configured with lvm"
		GETVOLUME="$(lsblk -r| grep -e 'store$'| cut -d " " -f 1)"
		info "Checking XFS for store partition - ${RED}PARTITION${NC}"
		$XFS /dev/$GETVOLUME 2>&1 | tee -a $LOG  > /dev/null
	fi
#
#Second is it HA or not **ISHAACTIVE**
#
subtitle "HA Checks ${DEST}/${MYH}_HA.log"
	echo "Is HA active?" 2>&1 | tee -a ${DEST}/${MYH}_HA.log
	systemctl is-active ha_manager >/dev/null
	[ $? -eq 0 ] && ISHAACTIVE="true" || ISHAACTIVE="false"
	if [ $ISHAACTIVE == "true" ]
	then
		echo "HA is Active"  2>&1 | tee -a ${DEST}/${MYH}_HA.log
		echo "ha_diagnosis command" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
		/opt/qradar/support/ha_diagnosis.sh 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
		echo "DRBD Conf" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
 		cat /etc/drbd.conf 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
 	else
 		echo "HA is not Active" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
 	fi
#
#Third is bonding configured **ISBONDINGEXIST**
#
	echo "Is Bonding configured?" 2>&1 | tee -a ${DEST}/${MYH}_HA.log
	BONDINGINTERFACE=$($NTTUNE linkaggr list | grep -v "No")
	[[ $BONDINGINTERFACE ]] && ISBONDINGEXIST="true" || ISBONDINGEXIST="false"
	
	if [ $ISBONDINGEXIST == "true" ]
	then
		echo "Bonding configured" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
		$NTTUNE linkaggr $BONDINGINTERFACE status 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
	else
		echo "Bonding NOT configured" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
	fi

#
#Fourth is crosssover configured **ISCROSSOVEREXIST**
#
	echo "Is Crossover configured?" 2>&1 | tee -a ${DEST}/${MYH}_HA.log
	ISCROSSOVERENABLE=$($NTTUNE crossover status | grep -v "not configured")
	[[ $ISCROSSOVERENABLE ]] && ISCROSSOVEREXIST="true" || ISCROSSOVEREXIST="false"
	if [ $ISCROSSOVEREXIST == "true" ]
	then
		echo "Crossover configured" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
		$NTTUNE crossover status 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
		$NTTUNE crossover test link 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
	else
		echo "Crossover NOT configured" 2>&1 | tee -a ${DEST}/${MYH}_HA.log > /dev/null
	fi
#
#Deployment Information GENERAL CHECK ON ALL Deployment
title "Deployment Information"
	subtitle "General Health information"
		info "How many times I am Up?"
		$UPT 2>&1 | tee -a $LOG > /dev/null
		$TOP -n1 -b |head -n +6 2>&1 | tee -a $LOG > /dev/null
		echo "Remember I have $(cat /proc/cpuinfo | grep "model name" | wc -l) CPU Thread" 2>&1 | tee -a $LOG > /dev/null
		info "Getting LSBLK info"
		$LSBLK -o MAJ:MIN,NAME,FSTYPE,UUID,MODEL,SIZE,TYPE,MOUNTPOINT,VENDOR,WWN 2>&1 | tee -a $LOG > /dev/null
		info "Getting BLKID info"
		$BLK 2>&1 | tee -a $LOG > /dev/null
		info "LAVG, CPU, RAM, DISK sar command. Output at ${DEST}/${MYH}_sar.output"
		echo ":Load Average Stats"  2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$SAR -q 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		echo ":CPU Performance"  2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$SAR -u 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		echo ":RAM Performance"  2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$SAR -r 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		echo ":RAM Swap Usage" 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$SAR -S 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		echo ":All DM Named DISK Information" 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		for i in $(ls /dev/dm*)
		do 
			echo "$i "  2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
			dmsetup info $i | grep -e "Name" -e "State" -e "Major, minor:"  2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		done
		echo ":DISK Performance -1 " 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$SAR -d -p 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		echo ":DISK Performance -2 " 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$SAR -d 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		echo ":DISK Performance with iostat"  2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		$IOSTAT -xm 5 10 2>&1 | tee -a ${DEST}/${MYH}_sar.output > /dev/null
		info "Checking DISK Usages"
		$DF -Th -t xfs 2>&1 | tee -a $LOG > /dev/null
		info "Checking DISK Inode Usages"
		$DF -Thi -t xfs 2>&1 | tee -a $LOG > /dev/null
		#HEA:WillCheck info "Maximum Disk Queue Size group by hostname and disk" 2>&1 | tee -a $LOG
		#HEA:WillCheck select Hostname,Element,max(Value) from events where qid='94000001' and "Metric ID"='DiskQueueSize' and Value <> 0 group by "Hostname","Element" 2>&1 | tee -a $LOG > /dev/null
		#HEA:WillCheck  info "Disk Space Sentinel logs"
		#HEA:WillCheck  grep com.q1labs.hostcontext.ds.DiskSpaceSentinel /var/log/qradar.log 2>&1 | tee -a ${DEST}/${MYH}_diskspacesentinel.logs >/dev/null
		#HEA:Willcheck echo "You can find output at ${DEST}/${MYH}_diskspacesentinel.logs "  2>&1 | tee -a $LOG >/dev/null
		info "What is my version and interim fix?"
		$MYVER -hash 2>&1 | tee -a $LOG > /dev/null
		info "Checking QRadar Appliance EOS"
		[ $AMICONSOLE == "true" ] && check_qradar_eos
#
	subtitle "Disk Write Read Tests"
		info "Checking  Disk Write Performance. Output at ${DEST}/${MYH}_qradar_sequential_write_test.log "
		$FIO --name=qradar_mix_write_io --directory=/store/ariel/events --ioengine=libaio --iodepth=64 --rw=write --output=${DEST}/${MYH}_qradar_sequential_write_test.log -bs=4k --direct=1 --size=1G --numjobs=8 --runtime=60 --group_reporting
		clear
		info "Checking Disk Read Performance. Output at ${DEST}/${MYH}_qradar_random_read_test.log"
		$FIO --name=qradar_mix_read_io --directory=/store/ariel/events --ioengine=libaio --iodepth=64 --rw=randread --output=${DEST}/${MYH}_qradar_random_read_test.log -bs=4k --direct=1 --size=1G --numjobs=8 --runtime=60 --group_reporting
		rm -f /store/ariel/events/qradar_mix_write_io*
		rm -f /store/ariel/events/qradar_mix_read_io*
		clear
#
	subtitle "Network Information"	
		echo ":Getting ifconfig output for Management Interface" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
		$IFC $MGMTINT 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
		echo ":Getting ethtool output for Management Interface" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
		$ETHTOOL $MGMTINT 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
		$ETHTOOL -S $MGMTINT 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
		echo ":Getting Hostname Information" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
		$HNAME 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
#
	subtitle "Collecting important informations"
		info "Copy important files"
		$CP /var/log/qradar.log ${DEST}/${MYH}_qradar.log
		$CP /var/log/qradar.error ${DEST}/${MYH}_qradar.error
		$FIND /var/log/qradar.old/ -regex '.*qradar\.log\.[0-9]\.gz' -exec cp {} ${DEST}/ \;
		$FIND /var/log/qradar.old/ -regex '.*qradar\.error\.[0-9]\.gz' -exec cp {} ${DEST}/ \;
		$CP /opt/qradar/conf/capabilities/hostcapabilities.xml ${DEST}/${MYH}_hostcapabilities.xml
		$CP /opt/qradar/conf/nva.conf ${DEST}/${MYH}_nva.conf
		$CP /opt/qradar/conf/deployment.xml ${DEST}/${MYH}_deployment.xml
#
	subtitle "Getting Hashes"
		info "Collecting my own host token"
		cat /opt/qradar/conf/host.token | java -jar /opt/qradar/jars/ibm-si-mks.jar decrypt_command_line 2>&1 | tee -a $LOG > /dev/null 
	subtitle "Is Encryption btw hosts exist?"
		$MYVER -tunnel 2>&1 | tee -a $LOG > /dev/null 
#
	subtitle "Log File Check"
	echo "Getting ExpensiveCustomRules Information from Logs. This may take a while"
	info "Exception Reading CRE Rules check from logs"
	echo "Exception Reading CRE Rules check from logs" 2>&1 | tee -a ${DEST}/${MYH}_rule_read_exception.log > /dev/null	
 	grep -i "Exception Reading CRE Rules" /var/log/qradar.error 2>&1 | tee -a ${DEST}/${MYH}_rule_read_exception.log > /dev/null
	info "Check ${DEST}/${MYH}_rule_read_exception.log file for output"
	info "Expensive Custom Rules Based On Average Throughput check from logs"
	echo "Expensive Custom Rules Based On Average Throughput check from logs" 2>&1 | tee -a ${DEST}/${MYH}_expensive_custom_rule.log > /dev/null
	grep -i "Expensive Custom Rules Based On Average Throughput" /var/log/qradar.error 2>&1 | tee -a ${DEST}/${MYH}_expensive_custom_rule.log > /dev/null
	info "Expensive Custom Rules"
	grep -i "Expensive Custom Rules" /var/log/qradar.log | tail -10 2>&1 | tee -a ${DEST}/${MYH}_expensive_custom_rule.log > /dev/null
	info "Custom Rule Engine Error check 1 from logs"
	grep -i "Custom Rule Engine has detected a total of" /var/log/qradar.error | tail -10 2>&1 | tee -a ${DEST}/${MYH}_cre_error.log > /dev/null
	info "Custom Rule Engine Error check 2 from logs"
	grep -i "com.q1labs.semsources.cre.CustomRule: \[ERROR\]" /var/log/qradar.error  | tail -10 2>&1 | tee -a ${DEST}/${MYH}_cre_error.log > /dev/null
	echo "Check ${DEST}/${MYH}_cre_error.log file for output" 2>&1  | tee -a $LOG >/dev/null
	#
	subtitle "PSQL DB Health"
		info "DB Sizes (Table/DB) ${DEST}/${MYH}_psql_db_health.output" 
		psql -U qradar -c "select * from q_table_size order by mb desc limit 10"  2>&1 | tee -a  ${DEST}/${MYH}_psql_db_health.output > /dev/null
		psql -U qradar -c "select * from q_db_size" 2>&1 | tee -a  ${DEST}/${MYH}_psql_db_health.output > /dev/null
	#
	subtitle "Service Start Stop Logs for existing one"
		grep "systemd\[1\]" /var/log/qradar.log 2>&1 | tee -a ${DEST}/${MYH}_servicestartstop.log > /dev/null
		info "Service Start Stop Logs for old one"
		$FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz' -exec zgrep "systemd\[1\]" {} \;  \; 2>&1 | tee -a ${DEST}/${MYH}_servicestartstop.log > /dev/null
	#
	subtitle "Search for error and performance issues in logs"
		info "Replication Logs. Output at ${DEST}/${MYH}_replication.log"
		grep "Replication download" /var/log/qradar.log | head  2>&1 | tee -a ${DEST}/${MYH}_replication.log > /dev/null
		echo "Config Download Stats" 2>&1 | tee -a ${DEST}/${MYH}_replication.log > /dev/null
		$JMX -p 7778 -b "com.q1labs.hostcontext:application=hostcontext.hostcontext,type=Configuration" 2>&1 | tee -a ${DEST}/${MYH}_replication.log > /dev/null
	#
	subtitle "Pipeline Logs"
		echo "Pipeline in current log" 2>&1 | tee -a ${DEST}/${MYH}_pipelinestatus.log > /dev/null
		grep -i 'Pipeline' /var/log/qradar.log | sed -s 's/::fff.*-]//'  2>&1 | tee -a ${DEST}/${MYH}_pipelinestatus.log > /dev/null
		echo "Pipeline in Old Logs" 2>&1 | tee -a ${DEST}/${MYH}_pipelinestatus.log > /dev/null
		$FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz' -exec zgrep com.q1labs.sem.monitors.PipelineStatusMonitor {} \; 2>&1 | tee -a ${DEST}/${MYH}_pipelinestatus.log > /dev/null
	#	
	subtitle "DSM Directly to storage logs. Output at ${DEST}/${MYH}_dsmdirectlytostorage.log "
		cat /var/log/qradar.log | grep "Device Parsing has sent a total of" | grep "directly to storage" 2>&1 | tee -a ${DEST}/${MYH}_dsmdirectlytostorage.log  > /dev/null
		$FIND /var/log/qradar.old -regextype sed  -regex '.*qradar\.log\.[0-9]\{1,2\}\.gz' -print0 | xargs -0 zgrep "Device Parsing has sent a total of" 2>&1 | tee -a ${DEST}/${MYH}_dsmdirectlytostorage.log  > /dev/null 
	#
	subtitle "Warn & Error messages"
		zcat /var/log/qradar.old info "WARN messages. Output at ${DEST}/${MYH}_warnmessages.log"
		grep WARN /var/log/qradar.log  2>&1 | tee -a ${DEST}/${MYH}_warnmessages.log > /dev/null
		info "ERROR messages. Output at ${DEST}/${MYH}_errormessages.log"
		grep ERROR /var/log/qradar.log  2>&1 | tee -a ${DEST}/${MYH}_errormessages.log > /dev/null
	#
	subtitle "Extention Most to least expensive. Ouput at ${DEST}/${MYH}_extensions_based_on_average_throughput.log "
		$FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz' -exec zgrep "Extensions Based on Average Throughput in the last 60 seconds"  {} \; 2>&1 | tee -a ${DEST}/${MYH}_extensions_based_on_average_throughput.log > /dev/null
	#
	title "Check for services status"
	/opt/qradar/upgrade/util/setup/upgrades/wait_for_start.sh  2>&1 | tee -a ${DEST}/${MYH}_waitfor.log > /dev/null
	#EXCEPT DATANODE RUN ON ALL
	if [ "${MYROLE}" != "datanode" ]
	then
	subtitle "Is there any Persistent Queue"
		$DU -chaxd1 /store/persistent_queue/ 2>&1 | tee -a $LOG > /dev/null
	subtitle "Checking OS Info"
		java -cp /opt/qradar/jars/q1labs_supportability_tools.jar com.ibm.si.qradar.supportability.DumpMBeanData -h localhost -p 7777 -d java.lang -b type=OperatingSystem --json 2>&1 | tee -a $LOG > /dev/null
	subtitle "Getting failure information on rules and expensive check except datanodes" 
		info "CRE Failure checks"
		$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=CustomRuleReader" 2>&1 | tee -a ${DEST}/${MYH}_cre_failure_check.log > /dev/null
	fi
#
#IF ON CONSOLE
#
if [ $AMICONSOLE == "true" ]
then
	if [ $DEPLOYMENTIS == "distributed" ]
	then
		title "Network Information and Stats. Output at ${DEST}/${MYH}_network_info_and_stats.logs"
			subtitle "Getting Network Speed and Stress test on SSH Connectivity"
				echo  ":Network Speed Test." 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs >/dev/null
				$TRUNCATE -s 1G /root/test.txt >/dev/null # Create file
				for mymh in ${MyMHs[@]}
				do 
					echo "::Measuring upload speed for $mymh" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs >/dev/null
					scp -v /root/test.txt ${mymh}:/root/  2>&1 | tee -a ${DEST}/upload.txt >/dev/null
					up_speed="$(cat ${DEST}/upload.txt | grep "Bytes per second" | sed "s/^[^0-9]*\([0-9.]*\)[^0-9]*\([0-9.]*\).*$/\1/g")"
					up_speed_in_mb="$(echo "${up_speed}/1000/1000" | bc)"
					echo "::Upload speed is measured as $up_speed_in_mb MBps for $mymh" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
					rm -f ${DEST}/upload.txt
					echo "::How much time it takes to ssh to the MH" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
					$(which tracepath) -b $mymh -p 22 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
					echo "::SSH Check for $mymh " 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
					sshcount=0
					for i in $(seq 1 10)
					do 
						ssh $mymh -x "uname -a" > /dev/null 
						if [ $? -eq 0 ]
						then
							sshcount=$(echo $sshcount + 1  | bc)
						fi
					done
				echo "::Total ssh for $mymh counted $sshcount of 10" 2>&1 | tee -a ${DEST}/${MYH}_network_info_and_stats.logs  > /dev/null
				done
				$ALLS -C "rm -f /root/test.txt" >/dev/null # Deleting files which created
	fi
	subtitle "Hash values for important files"
		hashcollect
		hosttokens
	subtitle "Using deployment_viewer"
		info "Collecting deployment_viewer output"
		echo "all" | /opt/qradar/support/deployment_viewer.py -v   2>&1 | tee -a $LOG >/dev/null
	subtitle "Retention Bucket"
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Range: items=0-49' -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/config/event_retention_buckets?fields=name%2Cdeletion%2C%20database%2Cperiod&filter=enabled%3D%22true%22"  2>&1 | tee -a $LOG > /dev/null
	subtitle "Notifications Views"
		notificationviewstatus
	subtitle "Backup Status"
		psql -U qradar -c "select host_id,type,to_timestamp(time_initiated/1000) as stime, to_timestamp(time_completed/1000) as etime,initiated_by_user,status from backup where status='SUCCESS' order by stime limit 50" 2>&1 | tee -a $LOG > /dev/null
	subtitle "License Information"
		psql -U qradar -c "select hostname,ip,allocated_eps_rate,allocated_fps_rate,average_eps_rate,average_fps_rate,peak_eps_rate,peak_fps_rate,to_timestamp(last_calculation_time/1000) as lastcalculationtime from license_pool_allocation left join serverhost on serverhost.id=license_pool_allocation.host_id;" 2>&1 | tee -a $LOG > /dev/null
		#HEA:Will Check subtitle "Getting last patch status"
		#HEA:Will Check myverforpatch=$(/opt/qradar/bin/myver)
		#HEA:Will Check cat /var/log/setup-${myverforpatch}/patches.log  | grep -e "^$(hostname -s)" | grep  -v test  2>&1 | tee -a $LOG >/dev/null
	subtitle "Top Rules"
		echo "Top Rule Output at ${DEST}/${MYH}_toprules.log" 2>&1 | tee -a $LOG >/dev/null
		echo "Top Rules from Health Data" 2>&1 | tee -a ${DEST}/${MYH}_toprules.log >/dev/null
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Range: items=0-49' -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/health_data/top_rules" | $JQ "." 2>&1 | tee -a ${DEST}/${MYH}_toprules.log > /dev/null
		echo "Top Rules from Analytics Rules ${DEST}/${MYH}_toprules.log" 2>&1 | tee -a ${DEST}/${MYH}_toprules.log >/dev/null 
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/analytics/rules?fields=average_capacity%2C%20base_capacity%2Cowner%2Cidentifier%2C%20origin%2C%20name&filter=average_capacity%20%3E%200%20and%20enabled%3Dtrue"| jq -s '.[] | sort_by(.average_capacity) | reverse' 2>&1 | tee -a ${DEST}/${MYH}_toprules.log > /dev/null
	subtitle "Top Offenses"
		echo "Top Offenses Output at ${DEST}/${MYH}_topoffenses.log" 2>&1 | tee -a $LOG >/dev/null
		echo "Offenses has most event count (Top 10)" 2>&1 | tee -a ${DEST}/${MYH}_topoffenses.log >/dev/null
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Range: items=0-10' -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/health_data/top_offenses" |  $JQ -s '.[] | sort_by(.count) | reverse' 2>&1 | tee -a ${DEST}/${MYH}_topoffenses.log > /dev/null
		echo "Top Rules Contributing Offenses"  2>&1 | tee -a ${DEST}/${MYH}_topoffenses.log >/dev/null
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Range: items=0-10' -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/analytics/rules_offense_contributions" | $JQ -s '.[]| sort_by(.event_count)| reverse' 2>&1 | tee -a ${DEST}/${MYH}_topoffenses.log > /dev/null
	subtitle "Security Artifacts "
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/health_data/security_artifacts.log" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
	subtitle "Getting Deployment Hosts with Components Information"
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/config/deployment/hosts?fields=id%2Chostname%2Cstatus%2Cprivate_ip%2Cappliance%2Cversion%2Cprimary_server_id%2Csecondary_server_id%2Ccomponents%2Cencryption_enabled%2Ccpus%2Ctotal_memory%2Capp_memory&filter=status%20%3C%3E%20%22Deleted%22" | $JQ '.' 2>&1 | tee -a ${DEST}/${MYH}_deployment_overview.log > /dev/null
		echo "You can find output at ${DEST}/${MYH}_deployment_with_components.log" 2>&1 | tee -a $LOG  > /dev/null
	subtitle "Getting Event Collectors and its ID Information"
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/config/event_sources/event_collectors" | $JQ "." 2>&1 | tee -a ${DEST}/${MYH}_deployment_overview.log > /dev/null
		echo "You can find output at ${DEST}/${MYH}_eventcollectors_and_ids.log" 2>&1 | tee -a $LOG  > /dev/null
	subtitle "Are there any DLC exist?"
		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/config/event_sources/disconnected_log_collectors" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
	subtitle "Checking Last Deploy Status"
 		$CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://$DefinedIPConsole/api/staged_config/deploy_status" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
	subtitle "Finding Most Populated Reference Sets and their association with rules exist?"
		psql -U qradar -c " select rd.name,to_timestamp(created_time/1000) as Creationtime,timeout_type,time_to_live,current_count as HowManyElements,count(rdr.id) as AssociatedRules from reference_data_rules as rdr left join reference_data as rd on rd.id=rdr.rd_id group by name,CreationTime,timeout_type,time_to_live,HowManyElements order by HowmanyElements desc limit 10 ;" 2>&1 | tee -a $LOG > /dev/null
		subtitle "Network Hierarchy Information"
	subtitle "Finding How many Network Hierarchy Item exist?"
		psql -U qradar -c "select count(*) from network;"  2>&1 | tee -a $LOG > /dev/null
	subtitle "Finding private IP address range not defined in Network Hierarchy"
		localiplistlistedotherinnh
	subtitle "Psql output for deployment"
		info "Managed and ServerHosts Tables ${DEST}/${MYH}_deployment_overview.log" >/dev/null
		psql -U qradar -c "select m.id as mid,s.id as sid,m.hostname,m.status as mstatus,s.status as sstatus,m.creationdate,s.updatedate,m.qradar_version,m.primary_host,m.secondary_host,s.managementinterface,s.cpus,s.total_memory as memory from managedhost as m left join serverhost as s on s.managed_host_id=m.id where s.status=0;" 2>&1 | tee -a ${DEST}/${MYH}_deployment_overview.log > /dev/null
	subtitle "Tomcat Service Check"
		$SYSCTL status tomcat --full	2>&1 | tee -a ${DEST}/${MYH}_tomcat_service_status > /dev/null
  		echo "-----------------------" 2>&1 | tee -a ${DEST}/${MYH}_tomcat_service_status > /dev/null
  		$JCTL -u tomcat -r --no-pager 2>&1 | tee -a ${DEST}/${MYH}_tomcat_service_status > /dev/null
  		echo "You can find output at ${DEST}/${MYH}_tomcat_service_status" 2>&1 | tee -a $LOG > /dev/null
  	subtitle "Expensive Custom Properties or Custom Properties Disabled"
  		expensivecustomproperties
fi

if [ "$MYROLE" == "eventprocessor" ] || [ "$MYROLE" == "eventcollector" ] || [ "$MYROLE" == "eventandflowprocessor" ] || [ "$MYROLE" == "console" ]
then
	##########################################
	## EVENTPIPELINE #########################
	##########################################
	title "Event Pipeline Controls"
	#####################
	## HOSTCONTEXT
	#####################
	subtitle "EventPipeline: Collecting Hostcontext Information"
		info "Hostcontext all services output ${DEST}/${MYH}_hostcontext_service.(json|output)"
		$JMX -p 7778 -b "com.q1labs.hostcontext:application=hostcontext.hostcontext,type=ProcessManager,processId=*" --json | $JQ '.' 2>&1 | tee -a ${DEST}/${MYH}_hostcontext_service.json >/dev/null
		info "Service status"
		$SYSCTL status hostcontext --full 2>&1 | tee -a $ ${DEST}/${MYH}_hostcontext_service.output > /dev/null
		info "Hostcontext Journalctl output"
		$JCTL -u hostcontext -r --no-pager 2>&1 | tee -a ${DEST}/${MYH}_hostcontext_service.output >/dev/null
	#####################
	## ECS-EC-INGRESS
	#####################
	subtitle "EventPipeline: Collecting ECS-EC-INGRESS Information"
		info "Service Status ${DEST}/${MYH}_ecs_ec_ingress_service.output"
		$SYSCTL status ecs-ec-ingress --full  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_service.output > /dev/null
		info "Journalctl Output ${DEST}/${MYH}_ecs_ec_ingress_service.output"
		$JCTL -u ecs-ec-ingress -r --no-pager  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_service.output > /dev/null
		#echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output > /dev/null
		#echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output > /dev/null
		#systemd-cgtop -b -n 5  /system.slice/ecs-ec-ingress.service 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output > /dev/null
		info "EPS Throttle ${DEST}/${MYH}_ecs_ec_ingress_throttle.json"
		for i in $(seq 1 10)
		do
			$JMX -p 7787 -b 'com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=filters,name=Event Throttle,eca=EC_Ingress' --json  | jq '.' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_throttle.json > /dev/null
			$JMX -p 7787 -b 'com.q1labs.frameworks.queue:application=ecs-ec-ingress.ecs-ec-ingress,id=EventThrottleFilterQueue' --json | jq '.' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_throttle.json > /dev/null
			sleep 5
		done
		#
		#echo "How many Connection we have"
		#$JMX -p 7778 -b "com.q1labs.hostcontext.sar:application=hostcontext.hostcontext,type=NetstatReport,name=netstat" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output > /dev/null
		info  "ECS-EC-INGRESS Event Rates (Source Monitor) ${DEST}/${MYH}_ecs_ec_ingress_sourcemonitor.log"
		cat /var/log/qradar.log | grep -i ecs-ec-ingress.ecs-ec-ingress | grep com.q1labs.sem.monitors.SourceMonitor  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_sourcemonitor.log > /dev/null
		info  "ECS-EC-INGRESS Event Rates on Old Files"
		#HEA:Will Remove for i in $(find /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz')
		#HEA:Will Remove do
		#HEA:Will Remove echo "Checking $i file" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output > /dev/null
		#HEA:Will Remove zcat $i | grep -i ecs-ec.ingress | sed -n 's/^\(.\{15\} \).*\((60s: [0-9\.]\{1,\} eps)\).*\(Peak.*60s: [0-9\.]\{1,\} eps\).*\(Max Seen [0-9\.]\{1,\} eps\).*\(Threshold: [0-9\.]\{1,\}\).$/\1 \2 \3 \4/p'| head -1 2>&1 | tee -a $LOG > /dev/null
		#HEA:Will Remove done
		for i in $($FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz')
		do
			zgrep com.q1labs.sem.monitors.SourceMonitor $i | grep ecs-ec-ingress.ecs-ec-ingress 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_sourcemonitor.log > /dev/null	
		done
		#
		subtitle "Getting ECS-EC-INGRESS stats using JMX. Take a while ${DEST}/${MYH}_ecs_ec_ingress_jmx_*.json"
		info "Collecting ECS_EC_INGRESS Queues statistics ${DEST}/${MYH}_ecs_ec_ingress_jmx_queues.json"
		$JMX -p 7787 -b "com.eventgnosis:type=EC_Ingress Queues,name=*" --json | $JQ '.mbean | to_entries[] | select(.value.attributes.EventsPosted != "0")'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_queues.json > /dev/null	
		#info "Collecting Filter Queue statistics" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output
		#$JMX -p 7787 -d "com.q1labs.frameworks.queue" --json | $JQ '.mbean | to_entries[]'   2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress.output > /dev/null
		info "Collecting Log Sources Types CurrentRate bigger than zero ${DEST}/${MYH}_ecs_ec_ingress_jmx_lshasvalue.json"
		$JMX -p 7787 -d "com.q1labs.sem" --json | $JQ '.mbean | to_entries[] | select((.value.attributes | has("CurrentRate")) and (.value.attributes.CurrentRate != "0.0"))' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_lshasvalue.json > /dev/null
		info "Getting ECS-EC-INGRESS Source Monitor ${DEST}/${MYH}_ecs_ec_ingress_jmx_sourcemonitor.json"
		for i in $(seq 1 10)
		do
			$JMX -p 7787 -b "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=Source Monitor" --json | jq '.' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_sourcemonitor.output > /dev/null
			sleep 5
		done
		info "Getting ECS-EC-INGRESS service OS consumptions ${DEST}/${MYH}_ecs_ec_ingress_jmx_osconsumption.json"
		$JMX -p 7787 -d "java.lang" -b "java.lang:type=OperatingSystem" -a SystemCpuLoad -a MaxFileDescriptorCount -a AvailableProcessors -a SystemLoadAverage -a OpenFileDescriptorCount  --json | jq '.mbean' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_osconsumption.json > /dev/null
		$JMX -d "java.lang" -b "java.lang:type=Memory" -a HeapMemoryUsage -a NonHeapMemoryUsage -a MaxHeapSizeLimit -a MaximumGCThreads -a CurrentGCThreads --json | jq '.mbean' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_osconsumption.json > /dev/null
		$JMX -p 7787 -b 'java.lang:type=Threading' -a ThreadCount -a PeakThreadCount -a CurrentThreadCpuTime --json | jq '.mbean' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_osconsumption.json > /dev/null
		info "Getting Sources Posted Events Stats ${DEST}/${MYH}_ecs_ec_ingress_jmx_sourcespostedstats.json"
		$JMX -p 7787 -b 'com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=*' --json | jq '.mbean | to_entries[] | select(.value.attributes.Posted != "0")'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_sourcespostedstats.json > /dev/null
		info "Getting Most SYSLOG Senders ${DEST}/${MYH}_ecs_ec_ingress_mostsyslogsender.output" 
		#HEA:Willcheck com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=*
		#HEA:Willcheck Posted
		#HEA:Willcheck NumberOfEventsPosted
		if [ $AMICONSOLE == "true" ]
		then
			$TDUMP -i any port 514 -nn -s0 -w /root/syslog_traffic.pcap -c 100 >/dev/null
		else
			$TDUMP -i any port 514 -nn -s0 -w /root/syslog_traffic.pcap -c 10000 >/dev/null
		fi
		#HEA: We will add logsource search for output of most syslog server on second column with using select hostname,devicename from sensordevice where hostname='$$'
		$TDUMP -r /root/syslog_traffic.pcap -nn 'dst port 514' | awk '{print $3}' | cut -d'.' -f1-4 | sort | uniq -c | sort -nr | head -n 10 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_mostsyslogsender.output > /dev/null
		rm -f /root/syslog_traffic.pcap
		info "ECS-EC-INGRESS TCP_TO_EP_PARSE ${DEST}/${MYH}_ecs_ec_ingress_jmx_tcp_to_ep_parse.json"
		for i in $(seq 1 10)
		do
			$JMX -p 7787 -b 'com.eventgnosis:type=EC_Ingress Queues,name=TCP_TO_ECParse' --json | jq '.' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_tcp_to_ep_parse.json > /dev/null
			$JMX -p 7787 -b 'com.q1labs.frameworks.queue:application=ecs-ec-ingress.ecs-ec-ingress,id=ecs-ec-ingress_EC_Ingress_TCP_TO_ECParse' --json | jq '.' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_ingress_jmx_tcp_to_ep_parse.json > /dev/null
			sleep 5
		done
	#####################
	## ECS-EC
	#####################
	subtitle "EventPipeline: Collecting ECS-EC Information"
		info  "Service status ${DEST}/${MYH}_ecs_ec_service.output"
		$SYSCTL status ecs-ec 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_service.output >/dev/null
		$JCTL -u ecs-ec -r --no-pager 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_service.output >/dev/null
		#echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec.output >/dev/null
		#echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec.output >/dev/null
		#systemd-cgtop -b -n 5  /system.slice/ecs-ec.service 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec.output >/dev/null
		info "Checking if all EventsSeen are Emmited in Event Parser ${DEST}/${MYH}_ecs_ec_event_emmited.output"
		$(which java) -cp /opt/qradar/jars/q1labs_supportability_tools.jar com.ibm.si.qradar.supportability.DumpMBeanData -h localhost -p 7777 -d com.q1labs.sem -b 'type=filters,name=DSM,threadid=Event Parser.*'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_event_emmited.output >/dev/null
		info "Regex and Its Use Conditions If exist ${DEST}/${MYH}_ecs_ec_regex_and_conditions.json"
		$(which java) -cp /opt/qradar/jars/q1labs_supportability_tools.jar com.ibm.si.qradar.supportability.DumpMBeanData -h localhost -p 7777 -d com.q1labs.sem -b 'application=ecs-ec.ecs-ec,name=DSM Extension,id=.*' --nobeanname -a Name -a UseCondition -a AverageParseTime --json | jq '.mbean| to_entries[]| select(.value.attributes.AverageParseTime != "0.0")' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_regex_and_conditions.json >/dev/null
	#
	subtitle "Getting ECS-EC stats using JMX. Take a while ${DEST}/${MYH}_ecs_ec_jmx_*.json"
		info "Collecting ECS-EC Queues statistics ${DEST}/${MYH}_ecs_ec_jmx_queue.json"
		$JMX -p 7777 -d "com.eventgnosis" --json | jq '.mbean | to_entries[] | select((.value.attributes | has("EventsPosted")) and (.value.attributes.EventsPosted != "0" ))' 2>&1 | tee -a  ${DEST}/${MYH}_ecs_ec_jmx_queue.json >/dev/null
		info "Collecting ECS-EC frameworks queue ${DEST}/${MYH}_ecs_ec_jmx_frameworks.json"
		$JMX -p 7777 -d "com.q1labs.frameworks.queue" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_jmx_frameworks.json >/dev/null
		info "DSM Parsing statistics ${DEST}/${MYH}_ecs_ec_jmx_dsmparsing.json" 
		$JMX -p 7777 -d "com.q1labs.sem" -b "application=ecs-ec.ecs-ec,type=filters,name=*" --json | jq '.mbean | to_entries[] | select((.value.attributes | has("EventsReceived")) and (.value.attributes.EventsReceived != "0"))' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_jmx_dsmparsing.json >/dev/null
		info "Getting ECS-EC service OS consumptions ${DEST}/${MYH}_ecs_ec_jmx_osconsumption.json"
		$JMX -p 7777 -d "java.lang" -b "java.lang:type=OperatingSystem" -a SystemCpuLoad -a MaxFileDescriptorCount -a AvailableProcessors -a SystemLoadAverage -a OpenFileDescriptorCount  --json | jq '.mbean'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_jmx_osconsumption.json >/dev/null
		$JMX -p 7777 -d "java.lang" -b "java.lang:type=Memory" -a HeapMemoryUsage -a NonHeapMemoryUsage -a MaxHeapSizeLimit -a MaximumGCThreads -a CurrentGCThreads --json  | jq '.mbean'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_jmx_osconsumption.json >/dev/null
		$JMX -p 7777 -b 'java.lang:type=Threading' -a ThreadCount -a PeakThreadCount -a CurrentThreadCpuTime --json | jq '.mbean' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_jmx_osconsumption.json >/dev/null
		info "DSM Unrecognized Rate Check ${DEST}/${MYH}_dsm_unrecognized_rate_check.json"
		dsm_unrecognized_rate_check
		info "Compression Information ${DEST}/${MYH}_ecs_ec_compression.output"
		$JMX -p 7777 -b "com.q1labs.sem:application=ecs-ec.ecs-ec,type=filters,name=Event Statistics" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_compression.output >/dev/null
		grep COMPRESS /opt/qradar/conf/nva.conf 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_compression.output >/dev/null
		info "Source Monitor Logs ecs-ec ${DEST}/${MYH}_ecs_ec_sourcemonitorlogs.output"
		cat /var/log/qradar.log | grep ecs-ec.ecs-ec | grep com.q1labs.sem.monitors.SourceMonitor 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_sourcemonitorlogs.output >/dev/null
		echo "Old ecs-ec sourcemonitor files" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_sourcemonitorlogs.output >/dev/null
	for i in $($FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz')
	do
		zgrep com.q1labs.sem.monitors.SourceMonitor $i | grep ecs-ec.ecs-ec  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_sourcemonitorlogs.output >/dev/null
		zgrep com.q1labs.sem.monitors.SourceMonitor $i | grep ecs-ec.ecs-ec  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_sourcemonitorlogs.output >/dev/null
	done
	info "StatFilter Logs from old files ${DEST}/${MYH}_ecs_ec_statfilterlogs.output"
	$FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz' -exec zgrep com.ibm.si.ec.filters.stat.StatFilter  {} \;  2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_statfilterlogs.output >/dev/null
	echo "StatFilter Logs from existing file" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_statfilterlogs.output
	grep com.ibm.si.ec.filters.stat.StatFilter /var/log/qradar.log 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_statfilterlogs.output >/dev/null
	info "Checking Spillover Logs ${DEST}/${MYH}_ecs_ec_spilloverlogs.output"
    cat /var/log/qradar.log |grep "com.ibm.si.ecingress.filters.QueuedEventThrottleFilter" | tail -10 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_spilloverlogs.output >/dev/null
   	#DSM Filter
	info  "DSM Filter Logs ${DEST}/${MYH}_ecs_ec_dsmfilterlogs.output"
	grep com.ibm.si.ec.filters.normalize.DSMFilter /var/log/qradar.log 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_dsmfilterlogs.output >/dev/null
	echo  "DSM Filter Logs from old files" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_dsmfilterlogs.output
	$FIND /var/log/qradar.old -regex '.*qradar\.log\.[0-9]+\.gz' -exec zgrep com.ibm.si.ec.filters.normalize.DSMFilter  {} \; 2>&1 | tee -a ${DEST}/${MYH}_ecs_ec_dsmfilterlogs.output >/dev/null

   	#HEA:WillCheck /opt/qradar/support/autodetection_config.py
   	#HEA:WillCheck this script show all autodetection is enabled or not. But ask for admin password
fi
#
# IF IT IS EVENTPROCCESSOR
if [ "$MYROLE" == "eventprocessor" ] || [ $AMICONSOLE == "true" ]
then
	#####################
	## ECS-EP
	#####################
	subtitle "EventPipeline: Collecting ECS-EP Information"
	info "Service status ${DEST}/${MYH}_ecs_ep.output"
	$SYSCTL status ecs-ep --full 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Journalctl output" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JCTL -u ecs-ep -r --no-pager 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	#echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	#echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	#systemd-cgtop -b -n 5  /system.slice/ecs-ep.service 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Event Throttle" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	for i in $(seq 1 10)
	do
		$JMX -p 7799 -b --json 'com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=Event Throttle,eca=MPC' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep_event_throttle.output >/dev/null
		$JMX -p 7799 -b --json 'com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=Event Throttle,eca=EP' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep_event_throttle.output >/dev/null
		sleep 5
	done
	info "Getting ECS-EP service OS consumptions ${DEST}/${MYH}_ecs_ep_jmx_osconsumption.json"
	$JMX -p 7777 -d "java.lang" -b "java.lang:type=OperatingSystem" -a SystemCpuLoad -a MaxFileDescriptorCount -a AvailableProcessors -a SystemLoadAverage -a OpenFileDescriptorCount  --json | jq '.mbean'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ep_jmx_osconsumption.json >/dev/null
	$JMX -p 7777 -d "java.lang" -b "java.lang:type=Memory" -a HeapMemoryUsage -a NonHeapMemoryUsage -a MaxHeapSizeLimit -a MaximumGCThreads -a CurrentGCThreads --json  | jq '.mbean'  2>&1 | tee -a ${DEST}/${MYH}_ecs_ep_jmx_osconsumption.json >/dev/null
	$JMX -p 7777 -b 'java.lang:type=Threading' -a ThreadCount -a PeakThreadCount -a CurrentThreadCpuTime --json | jq '.mbean' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep_jmx_osconsumption.json >/dev/null
	echo "Getting related stats for ECS-EP. Take a while" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output	
	echo "eventsgnosis Events has bigger than 0" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	$JMX -p 7799  -d com.eventgnosis --json | jq '.mbean| to_entries[]| select(.value.attributes | has("EventsPosted") and .value.attributes.EventsPosted != "0")' 2>&1 | tee -a ${DEST}/${MYH}_ecsep.output >/dev/null
	if  [ $AMICONSOLE == "true" ]
	then
	echo "MPC Queue Size" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.ibm.si.mpc:application=ecs-ep.ecs-ep,type=Magistrate Processing Core,aspect=Executors,id=DescriberAndAnnotator" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	$JMX -p 7799 -b "com.ibm.si.mpc:application=ecs-ep.ecs-ep,type=Magistrate Processing Core,aspect=Executors,id=CleanupAndPersistence"  2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Last Timer" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.ibm.si.mpc:application=ecs-ep.ecs-ep,type=Magistrate Processing Core,id=Magistrate Timer/Controller" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	fi
	echo "Event - Average Payload & Records Size" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.ariel:application=ecs-ep.ecs-ep,type=Database writer,a1=events-2" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Flow - Average Payload & Records Size" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.ariel:application=ecs-ep.ecs-ep,type=Database writer,a1=flows-1" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Ariel DB last re-index time" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.core:application=ecs-ep.ecs-ep,type=services,name=DBMaintenance,profile=hostcontext.startup,id=reindex-db/qradar" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Ariel DB last vacuum time" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.core:application=ecs-ep.ecs-ep,type=services,name=DBMaintenance,profile=hostcontext.startup,id=vacuum-full-db/qradar" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "CRE Threads" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=CRE*" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "ECS-EP EPS" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.sem:application=Event Processor,name=EP Monitor" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Event Throttle" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=Event Throttle*" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Events Stored Count"  2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=Event Storage" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	sleep 3
	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=Event Storage" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Rules Dropped Event Count bigger than 0" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
 	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,folder=RULES*" -a Name -a FiredCount -a TotalActionsCount -a TotalResponseCount -a AverageResponseTime -a AverageActionsTime -a AverageTestTime -a ReferenceDataResponseCount -a ReferenceSetResponseCount -a CapacityEps -a DropEventActionCount --json | jq '.mbean| to_entries[] | select(.value.attributes.DropEventActionCount != "0")' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Rules Fired Count bigger than 0" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,folder=RULES*" -a Name -a FiredCount -a TotalActionsCount -a TotalResponseCount -a AveragesponseTime -a AverageActionsTime -a AverageTestTime -a ReferenceDataResponseCount -a ReferenceSetResponseCount -a CapacityEps -a DropEventActionCount --json | jq '.mbean| to_entries[] | select(.value.attributes.FiredCount != "0")' 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Number of Rules never fired" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	$JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,folder=RULES*" -a Name -a FiredCount -a TotalActionsCount -a TotalResponseCount -a AverageResponseTime -a AverageActionsTime -a AverageTestTime -a ReferenceDataResponseCount -a ReferenceSetResponseCount -a CapacityEps -a DropEventActionCount --json | jq '.mbean| to_entries[] | select(.value.attributes.FiredCount = "0")' | grep key | wc -l 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "CRE Warn Rules Logs" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output
	cat /var/log/qradar.log | grep com.q1labs.semsources.cre.CRE | grep WARN 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo "Offenses has most event count (Top 10)"  2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	psql -U qradar -x -c "select event_count,active_code,naming_contributions,attacker_count,username_count,rule_id,regexp_matches(rule_data::text,'\<name\>(.*?)\<\/name\>'),regexp_matches(rule_data::text,'enabled=\"(.*?)\"') as enabled from offense as o left join custom_rule as c on c.id=o.rule_id  order by event_count desc limit 10;" 2>&1 | tee -a ${DEST}/${MYH}_ecs_ep.output >/dev/null
	echo  "You can find output at ${DEST}/${MYH}_ecs_ep.output"  2>&1 | tee -a $LOG >/dev/null
fi
	#####################
	## ACCUMULATOR
	#####################
	subtitle "EventPipeline: Collecting Accumulator Information"
	info  "Collect GVstat. Output at ${DEST}/${MYH}_accumulator.output"
	/opt/qradar/support/collectGvStats.sh -s 2>&1 | tee -a  ${DEST}/${MYH}_accumulator.output >/dev/null
	#####################
	## ARIEL_PROXY-SERVER
	#####################

	subtitle "Ariel_Proxy Service Details"
		$SYSCTL  status ariel_proxy_server.service  --full 2>&1 | tee -a ${DEST}/${MYH}_arielproxy.output > /dev/null
		$JMX -p 7778 -b "com.q1labs.hostcontext:application=hostcontext.hostcontext,type=ProcessManager,processId=ariel_proxy_server.ariel_proxy" 2>&1 | tee -a ${DEST}/${MYH}_arielproxy.output > /dev/null
		echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}-arielproxy.output > /dev/null
		echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_arielproxy.output > /dev/null
		#systemd-cgtop -b -n 5  /system.slice/ariel_proxy_server.service 2>&1 | tee -a ${DEST}/${MYH}_arielproxy.output > /dev/null
		echo "You can find output at ${DEST}/${MYH}_arielproxy.output"  2>&1 | tee -a $LOG > /dev/null

	#####################
	## ARIEL_QUERY_SERVER
	#####################
	subtitle "Ariel_Query Service Details"
		$SYSCTL  status ariel_query_server.service  --full 2>&1 | tee -a ${DEST}/${MYH}_arielquery.output > /dev/null
		echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}_arielquery.output > /dev/null
		echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_arielquery.output > /dev/null
		#systemd-cgtop -b -n 5  /system.slice/ariel_query_server.service 2>&1 | tee -a ${DEST}/${MYH}_arielquery.output > /dev/null
		echo "You can find output at ${DEST}/${MYH}_arielquery.output"  2>&1 | tee -a $LOG > /dev/null
	#####################
	## TUNNEL-MANAGER
	#####################
	subtitle "Tunnel Manager Service Details"
		$SYSCTL  status tunnel_manager.service  --full 2>&1 | tee -a ${DEST}/${MYH}_tunnelmanager.output > /dev/null
		echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}_tunnelmanager.output > /dev/null
		echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_tunnelmanager.output > /dev/null
		#systemd-cgtop -b -n 5  /system.slice/ariel_proxy_server.service 2>&1 | tee -a ${DEST}/${MYH}_tunnelmanager.output > /dev/null
		echo "You can find output at ${DEST}/${MYH}_tunnelmanager.output"  2>&1 | tee -a $LOG > /dev/null
	#####################
	## TRAEFIK
	#####################
	subtitle "Traefik Service Details. Output at ${DEST}/${MYH}_traefik.output"
		$SYSCTL  status traefik.service  --full 2>&1 | tee -a ${DEST}/${MYH}_traefik.output > /dev/null
		echo "Systemcd-cgtop" 2>&1 | tee -a ${DEST}/${MYH}_traefik.output > /dev/null
		echo  "Control Group Tasks   %CPU   Memory Input/s Output/s" 2>&1 | tee -a ${DEST}/${MYH}_traefik.output > /dev/null
		#systemd-cgtop -b -n 5  /system.slice/traefik.service 2>&1 | tee -a ${DEST}/${MYH}_traefik.output > /dev/null
		echo "You can find output at ${DEST}/${MYH}_traefik.output"  2>&1 | tee -a $LOG > /dev/null



##########################################
## LOG SOURCES ###########################
##########################################
if [ $AMICONSOLE == "true" ]
then
title "Log Sources Info. Output at ${DEST}/logsourceinfo.log"
echo "DeviceType Name Grouped LS" 2>&1 | tee -a ${DEST}/logsourceinfo.log
psql -U qradar -c "select sdt.devicetypename, count(sd.id) from sensordevice as sd left join sensordevicetype as sdt on sd.devicetypeid=sdt.id where sd.deviceenabled='t' group by sdt.devicetypename order by count desc limit 10;" 2>&1 | tee -a ${DEST}/logsourceinfo.log > /dev/null
echo "Most EPS producing Log Sources (Top 10)" 2>&1 | tee -a ${DEST}/logsourceinfo.log
psql -U qradar -c "select devicename,eps60s,peakeps60s,timestamp_peakeps60s from sensordevice where deviceenabled='t' order by eps60s desc limit 10;" 2>&1 | tee -a ${DEST}/logsourceinfo.log > /dev/null
echo "EPS Rates per LogSources" 2>&1 | tee -a ${DEST}/logsourceinfo.log
epsratesperlsstatus
echo "Most EPS group by Device Type" 2>&1 | tee -a ${DEST}/logsourceinfo.log
psql -U qradar -c "select sdt.devicetypename, sum(sd.peakeps60s) from sensordevice as sd left join sensordevicetype as sdt on sdt.id=sd.devicetypeid where sd.deviceenabled='t' group by sdt.devicetypename order by sum desc limit 10;" 2>&1 | tee -a ${DEST}/logsourceinfo.log > /dev/null
echo "Log Sources (Enabled One)" 2>&1 | tee -a ${DEST}/logsourceinfo.log >/dev/null
psql -U qradar -c "select sd.id,sd.hostname,sd.devicename,sd.store_event_payload,eps60s as EPS60s,logonly,coalesce_events as Coalesced,to_timestamp(timestamp_last_seen/1000) as LastSeen,peakeps60s as PeakEPS,timestamp_peakeps60s as TimePeakEPS,devicetypename from sensordevice as sd left join sensordevicetype as sdt on sdt.id=sd.devicetypeid where deviceenabled='t' order by peakeps desc;" 2>&1 | tee -a ${DEST}/logsourceinfo.log > /dev/null
echo "Log Source Extention" 2>&1 | tee -a ${DEST}/logsourceinfo.log >/dev/null
psql -U qradar -c "select id,name,enabled,use_condition from device_ext where enabled='t';" 2>&1 | tee -a ${DEST}/logsourceinfo.log > /dev/null
fi

#SEARCHES ON CONSOLE
if [ $AMICONSOLE == "true" ]
then
	subtitle "Log Sources Unparsed Events, Droped Events, Unknown Log Sources"
    info "Log Sources Dropped Events"
    droppedevents=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750060%20LIMIT%2010%20last%2015%30DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    destatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${droppedevents}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    while [ true ]
    do
    	destatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${droppedevents}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "$destatus" == "COMPLETED" ]
    	then
    		echo -ne "\tDropped Events Search now $destatus           \r"
    		break
    	else 
    		echo -ne "\tDropped Events Search still in $destatus mode \r"
    	fi
    	sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${droppedevents}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    info "Unknown Log Sources"
    ulogsource=$($CURL -k -S -s --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750007%20LIMIT%2010%20last%201%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    ulstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${ulogsource}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    while [ true ]
    do
        ulstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${ulogsource}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        if [ "$ulstatus" == "COMPLETED" ]
        then
        	echo -ne "\tUnknown Log Sources Search now $ulstatus           \r"
        	break
        else
        	echo -ne "\tUnknown Log Sources Search still in $ulstatus mode \r"
        fi
       	sleep 5
    done
    echo ""
    $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${ulogsource}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    info "Unparsed Logs"
    unparsed=$($CURL -k -S -s --location --request POST "https://$DefinedIPConsole/api/ariel/searches?query_expression=select%20LONG%28count%28*%29%29%20as%20Total%20%2cLOGSOURCENAME%28logsourceid%29%20as%20LST%20from%20events%20where%20isunparsed%3DTrue%20group%20by%20LST%20order%20by%20Total%20ASC%20last%2015%20MINUTES" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
    upestatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${unparsed}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    while [ true ]
    do
    	upestatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${unparsed}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
    	if [ "$upestatus" == "COMPLETED" ]
    	then
    		echo -ne "\tUnparsed Logs Search now $upestatus          \r"
    		break
    	else
    		echo -ne "\tUnparsed Logs Search still in $upestatus mode\r"
    	fi
    	sleep 5
    done
    echo ""
	$CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$DefinedIPConsole/api/ariel/searches/${unparsed}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    echo ""
	#
    title "Wincollect Information."
	$RM -f /storetmp/wincollect/Win*
    title "Wincollect Information"
	$RM -f /storetmp/wincollect//WinCollectDeploymentSummaryResults*
	echo yes | /opt/qradar/support/WinCollectHealthCheck.sh -sl
	$MV /storetmp/wincollect/WinCollectDeploymentSummaryResults* ${DEST}/${MYH}_wincollect.log
fi    
#ENDSCRIPT
echo "$(date) $MYH finished" 2>&1 | tee -a ${DEST}/wedone >/dev/null
clear
#HEA:Will add extra control bu not needed now myscreenid=$(echo $STY)
echo "We completed HC on $MYH please find result in $DEST folder" 2>&1 | tee -a $LOG
#HEA:Will add extra control bu not needed now screen -X -S $myscreenid quit
#CONTROL and COMPRESS FILES
[ $AMICONSOLE = "false" ] && tar -cvf /root/healthcheck.tar /root/HealthCheck
[ $AMICONSOLE = "false" ] && gzip /root/healthcheck.tar
#POST RUN SCRIPT

controlrunningscriptonmhs
if [ $AMICONSOLE == "true" ] && [ $wedoneatall="yes" ]
then      	
	if [ "$DEPLOYMENTIS" == "distributed" ] 
	then
			if [ $MHGROUPREGEX == "ALL" ]
			then
				$ALLS -t 1 -g /root/healthcheck.tar.gz
				$ALLS -t 1 "rm -rf /root/HealthCheck /root/healthcheck.tar.gz /root/${SCRIPT}"
				tar -cvf console_healtcheck.tar ${DEST}/
				tar -cvf /root/all.tar /root/from-* /root/console_healtcheck.tar
				rm -rf ${DEST} from-*
				clear
				printf "We completed HC. Please find result in all.tar file. Please test using ${RED} tar -tvf all.tar ${NC} command"
			else
				$ALLS -t 1 -n "%${MHGROUPREGEX}%" -g /root/healthcheck.tar.gz 
				$ALLS -t 1 -n "%${MHGROUPREGEX}%" "rm -rf /root/HealthCheck /root/healthcheck.tar.gz /root/${SCRIPT}"
				tar -cvf /root/console_healtcheck.tar ${DEST}/
				tar -cvf /root/all.tar /root/from-* /root/console_healtcheck.tar
				rm -rf ${DEST} from-*
				clear
				printf "We completed HC. Please find result in all.tar file. Please test using ${RED} tar -tvf all.tar ${NC} command\n"
			fi
	fi
fi
