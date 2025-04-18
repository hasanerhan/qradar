#!/usr/bin/env bash
#ERHAN
# AUTHOR      : Hasan Erhan AYDINOGLU 
# EMAIL       : hasanerhan@hasanerhan.com 
# START DATE  : 2024/02/26
# UPDATE DATE : 2024/12/04
# VERSION     : Check REV variable
# DESCRIPTION : This script working on Console to shorten the time of data collection for Health Check. 
# CHANGELOG   : v1.0 First Publication
#   v1.1 Fixes applied
#   v1.2 Output file information added
#        Scripts seperated and managed host' script run from console
#   v1.3 Added JMX properties
#        Fixes on producing logs
#        Added check for Qradar commands 
#        Added AQL searches                 
#   v1.4 Fix on structure
#TODO:
#  Add Log Analysis
#  Check unknown events for known log source types (DSM) and if possible it' ratio to known events. 
clear
#BASE VARIABLES
REV="1.4"
DEST="/root/HealthCheck"
MYH=$(hostname -s)
LOG=${DEST}/${MYH}_hc.log
IPCon="10.0.8.230"
API_KEY="fa55f3ed-7c16-46d8-81e3-af10178cd04f"
API_VERSION="16.0"
#
isconsole
#
#Testing if mandatory variables defined
if [ -z $IPCon ]
then
echo -e "Console IP adress not defined. Exiting..."
exit 0
fi
if [ -z $API_KEY ]
then
echo -e "Console API_KEY not defined. Exiting..."
exit 0
fi
if [ -z $API_VERSION ]
then
echo -e "Console API_Version not defined. Exiting..."
exit 0
fi
#
#Screen or Tmux?
function testforscreenandtmux {
which screen > /dev/null
if [ $? -eq 0 ]
then
SCRS=$(which screen)
else
SCRT=$(which tmux)
fi
}
testforscreenandtmux
#
#Version Function
function version {
 clear
 echo -e "\tVERSION:$SCRIPT $REV"
 echo -e "\tAUTHOR : Hasan Erhan AYDINOGLU"
 echo -e "\tEMAIL  : hasan.erhan.aydinoglu@ibm.com"
}
#
#Section Function
function title {
  clear
  echo -e "\n## SECTION: $1" | tee -a $LOG >> /dev/tty
  sleep 2
}
#
#Sub Section Function
function subtitle {
 echo -e "\n## SUB-SECTION: $1" | tee -a $LOG >> /dev/tty
  sleep 2
}
#
#Info Function
function info {
echo -e "--## INFO: $1" | tee -a $LOG >> /dev/tty
sleep 2
 }
#
#Usage Function
function usage {
 clear
 version
 echo "Usage:"
 echo -e "\t-r :: Run the script"
 echo -e "\t-v :: Script Version"
 echo -e "\t-h :: Help (This information)"
 echo -e "\n"
}
#
# Show usage if there were no arguments passed
if [[ $@ =~ --help || $# -eq 0 ]]
then
        usage
        exit 0
fi
#
#Check if any store folder exist?
if [ ! -d /store ]; then
   clear
   echo "System not found any store partition and $DEST. Is QRadar installed? We are quiting..."
           exit 1
fi
#
# Getting information on store partiton about LVM or not.
function storevolume {
#
#Is it partition or lvm
lvs --noheadings -o lv_name | sed 's/ //g'| grep -e ^store$
if [ $? -eq 0 ];
then
 info "Store is lvm"
 getvolume="$(lvs -o lv_full_name,devices|grep -e '/store ' |awk {'print $2'} |cut -d\/ -f3|cut -d\( -f1)"
else
 info "Store is not lvm"
 getvolume="$(lsblk -r| grep -e '/store$'| cut -d " " -f 1)"
   fi
}
##################################
#####                        #####
##### Main Script start here #####
#####                        #####
##################################
function runscript {
#
#Clearing Section
clear
$RM -rf $DEST
$MKDIR -p $DEST
touch $LOG
#
#Getting MHs IP ADDRESS 
function isaio {
    mhcount=$(psql -U qradar -t -c "select count(ip) from managedhost where isconsole='f' and status='Active'")
    if [ $mhcount -gt 1 ]
    then
        echo "This is distributed environment" 2>&1 | tee -a $LOG > /dev/null
        echo "Getting MHs IP address"  2>&1 | tee -a $LOG
        declare -a MyMHs
        for mh in $(psql -U qradar -t -c "select ip from managedhost where isconsole='f' and status='Active'")
        do
            MyMHs+=($mh)
        done
        for mh in ${MyMHs[@]};
        do
            $SSH $mh -o ConnectTimeout=3 -x "echo"  >/dev/null
            if [ $? -ne 0 ];
            then
                subtitle "ssh is not successfull for mh deleting from array : $mh" | tee -a $LOG
                MyMHs=("${MyMHs[@]/$mh}")
            fi
        done
        for mymh in ${MyMHs[@]}
        do 
            echo "IP address of MHs detected as $mymh" 2>&1 | tee -a $LOG
            sleep 1
        done
    else 
        echo "This is AIO environment" 2>&1 | tee -a $LOG > /dev/null
    fi
}
##################################
#####                        #####
#####   Reports start here   #####
#####                        #####
##################################
#DEPLOYMENT
#Overall Information
title "Deployment"
    subtitle "Overall Information"
        info "Uptime"
            $UPT 2>&1 | tee -a $LOG > /dev/null
        info "Is AIO?"
            isaio
        info "QRadar Version"
            $MYVER -v | grep -e "^Appliance" -e "^Release name is" -e "^Version installed with" -e "^RPM external version is" -e "^IP address:" -e "^Virtual IP" -e "^Virtual Hostname" -e "^Operating System" -e "^FIPS enabled" 2>&1 | tee -a $LOG > /dev/null 
        info "Hostname"
            $HNAME 2>&1 | tee -a $LOG > /dev/null 
        info "IP"
            $IPC address show dev $MGMTINT 2>&1 | tee -a $LOG > /dev/null 
        info "Hostcapabilities"
            cat /opt/qradar/conf/capabilities/hostcapabilities.xml
        info "All Information for Deployment"
            psql -U qradar -c "SELECT distinct(dc.name),dc.managed_host_id as mh_id,mh.ip as mh_ip,sh.ip as sh_ip,sh.hostname,mh.appliancetype,sh.qradar_version,mh.creationdate,mh.primary_host,mh.secondary_host,sh.managementinterface as interface,sh.cpus,(sh.total_memory/1000/1024) as memory,sh.status as sh_status FROM deployed_component as dc left join managedhost as mh on mh.id=dc.managed_host_id left join serverhost as sh on sh.managed_host_id=mh.id WHERE mh.status='Active' and sh.status!='14' order by mh_id;" 2>&1 | tee -a $LOG > /dev/null
        info "Interim Fixes"
            cat /opt/qradar/conf/interimfix_list 2>&1 | tee -a $LOG > /dev/null 
        info "Patch?"
            cat /opt/qradar/conf/patch_list 2>&1 | tee -a $LOG > /dev/null 
        info "Encryption btw hosts exist?"
            $MYVER -tunnel 2>&1 | tee -a $LOG > /dev/null 
            echo -e "\nAnotherWay: $(grep '^HOST_ENCRYPTED=' /opt/qradar/conf/nva.conf)" 2>&1 | tee -a $LOG > /dev/null 
        info "Deployment Hosts"
            $CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://${IPCon}/api/config/deployment/hosts?fields=id%2Chostname%2Cstatus%2Cprivate_ip%2Cappliance%2Cversion%2Cprimary_server_id%2Csecondary_server_id%2Ccomponents%2Cencryption_enabled%2Ccpus%2Ctotal_memory%2Capp_memory&filter=status%20%3C%3E%20%22Deleted%22" | jq '.' 2>&1 | tee -a $LOG > /dev/null
        info "Event Collectors"
            $CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://${IPCon}/api/config/event_sources/event_collectors" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
        info "Disconnnected Log Collector"
            $CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://${IPCon}/api/config/event_sources/disconnected_log_collectors" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
        info "Deploy Status"
            $CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://${IPCon}/api/staged_config/deploy_status" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
        info "is store volume on lvm?"
            storevolume
        info "Check XFS"
            $XFS /dev/$getvolume 2>&1 | tee -a $LOG  > /dev/null
        info "Checking IOSTAT stats for " 
            counter=5
            echo "$getvolume as founded store partition" 2>&1 | tee -a $LOG  > /dev/null
            subtitle "IOSTAT running. This may take a while"
            while [ $counter -gt 0 ]; 
            do
            iostat -dmx  $getvolume 2>&1 | tee -a $LOG  > /dev/null
            echo -ne " $counter going to 0\r"
            sleep 10
                    counter=$(echo "$counter-1"|bc)
            done
    subtitle "Performance Statistics"
        info "CPU?"
            cat /proc/cpuinfo | grep "model name"| wc -l 2>&1 | tee -a $LOG > /dev/null
        info "Memory"
            free -m | grep '^Mem: ' | tr -s ' '| cut '-d ' -f2 2>&1 | tee -a $LOG > /dev/null
            free -m 2>&1 | tee -a $LOG > /dev/null
        info "Top Output"
            $TOP -n1 -b |awk -F, 'NR<7 {print $0}' 2>&1 | tee -a $LOG > /dev/null
        info "DISK Usage"
            $DF -Th 2>&1 | tee -a $LOG > /dev/null
        info "Spillover Logs"
                cat /var/log/qradar.log |grep "com.ibm.si.ecingress.filters.QueuedEventThrottleFilter" | tail -10  2>&1 | tee -a $LOG > /dev/null
    subtitle "Hardware Information"
        info "Getting Hardware Info. This may take a while"
            $DEPINFO -HJC 2>&1 | tee -a $LOG > /dev/null
        info "Getting Vendor Info"
            $DMI -t system | grep -e "Manufacturer" -e "Product Name" -e "Serial" 2>&1 | tee -a $LOG  > /dev/null
    subtitle "Network Information. This may take a while"
        if [ $mhcount -gt 1 ]
        then
            $TRUNCATE -s 1G /root/test.txt >/dev/null # Create file
            for mymh in ${MyMHs[@]}
            do 
                up_speed=$(scp -v /root/test.txt $mymh:/root/ 2>&1 | grep "Bytes per second" | sed "s/^[^0-9]*\([0-9.]*\)[^0-9]*\([0-9.]*\).*$/\1/g")
                up_speed=$(echo "$up_speed/1000000"|bc)
                echo "Measuring upload speed for $mymh"
                echo "Upload speed is measured as $up_speed MBps for $mymh" 2>&1 | tee -a $LOG  > /dev/null
                 for i in $(seq 1 10); do ssh $mymh uname -a > /dev/null;done;echo "Total ssh count=$i" 2>&1 | tee -a $LOG  > /dev/null
            done
            $ALLS -C "rm -f /root/test.txt" >/dev/null # Deleting files which created
        fi
        info "Hostname Information"
            echo "Hostnamectl" 2>&1 | tee -a $LOG > /dev/null
            $HNAME status 2>&1 | tee -a $LOG > /dev/null
            echo "Hostname" 2>&1 | tee -a $LOG > /dev/null
            $HSTN 2>&1 | tee -a $LOG > /dev/null
        info "Is Bonding Enabled?"
            echo "$MGMTINT" | grep bond > /dev/null
            if [ $? -eq 0 ]
            then
                echo "Bonding Enabled" 2>&1 | tee -a $LOG > /dev/null
            else 
                echo "Bonding Not Enabled" 2>&1 | tee -a $LOG > /dev/null
            fi
        info "Management Network"
            echo "$MGMTINT" 2>&1 | tee -a $LOG > /dev/null
        info "Management Speed"
            for i in $($IPC link | sed -rn 's/[[:digit:]]*:[[:space:]]+([[:alnum:]]+).*$/\1/p' | grep -ve lo -ve docker)
            do
                $ETHTOOL $i | grep -e "Speed:" -e "Duplex:" 2>&1 | tee -a $LOG > /dev/null
            done 
        info "EXTRA INFORMATION: IP Link List"
            $IPC link | sed -rn 's/[[:digit:]]*:[[:space:]]+([[:alnum:]]+).*$/\1/p' | grep -ve lo -ve docker  2>&1 | tee -a $LOG  > /dev/null
        info "EXTRA INFORMATION: Hosts written to hosts file"
            cat /etc/hosts 2>&1 | tee -a $LOG > /dev/null
        info "EXTRA INFORMATION: Route Information"
            $IPC route 2>&1 | tee -a $LOG > /dev/null
        info "EXTRA INFORMATION: Checking Load Average and Wait Time. This may take a while"
            counter=5
            while [ $counter -gt 0 ]; 
            do
                top -n1 -b |awk -F, 'NR==3 {print "USER:"$1 " IDLE:"$4 " WA:"$5}' | sed 's/Cpu(s)://g' 2>&1 | tee -a $LOG  > /dev/null
                echo -ne " $counter going to 0\r"
                sleep 10
                counter=$(echo "$counter-1"|bc)
            done
        info "EXTRA INFORMATION: Checking kernel errors"
            $DMESG -T | tail 2>&1 | tee -a $LOG  > /dev/null
    subtitle "Notifications Views"
        declare -a MYNOTVW
        MYNOTVW=($(for i in $(psql -t -U qradar -c "select distinct(qid)from notification_view limit 20;"); do echo $i;sleep 1 ;done))
        for mynotvw in ${MYNOTVW[@]}
        do
            systemloads=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D${mynotvw}%20order%20by%20starttime%20desc%20LIMIT%205%20last%202%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            slstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${systemloads}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            echo -e "\tNotification Search for $mynotvw in $slstatus mode" 2>&1 | tee -a $LOG 
            while [ true ]
            do
                slstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${systemloads}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
                sleep 5
                if [ "${slstatus}" == "COMPLETED" ]
                then
                    break
                fi
                echo -e "\tNotification Search for $mynotvw in $slstatus mode" 2>&1 | tee -a $LOG 
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${systemloads}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
done
    subtitle "Patch Status"
        $ALLS -C -X 2>&1 | tee -a $LOG > /dev/null
    subtitle "License Information"
        psql -U qradar -c "select hostname,ip,allocated_eps_rate,allocated_fps_rate,average_eps_rate,average_fps_rate,peak_eps_rate,peak_fps_rate,to_timestamp(last_calculation_time/1000) as lastcalculationtime from license_pool_allocation left join serverhost on serverhost.id=license_pool_allocation.host_id;" 2>&1 | tee -a $LOG > /dev/null
        info "EPS Rates per LogSources"
            msib=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20logsourcename%28logsourceid%29%20as%20%22LogSource%22,%20long%28SUM%28eventcount%29%29/3600%20AS%20%22EPS%22%20from%20events%20group%20by%20LogSource%20order%20by%20EPS%20desc%20LIMIT%2010%20last%2060%20MINUTES" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            status="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${msib}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            while [ true ]
            do
            status="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${msib}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            sleep 3
            if [ "$status" == "COMPLETED" ]
            then
            break
            fi
            echo "EPS per LogSource Search in $status mode"
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${msib}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    subtitle "Validation of Deployment"
        info "Validate deployment script"
            $VALDEP 2>&1 | tee -a $LOG > /dev/null
        info "Wait for service script"
            $WFS 2>&1 | tee -a $LOG > /dev/null
        info "EXTRA INFORMATION: Tomcat journalctl"
             $JCTL-u tomcat -r --no-pager|grep failed| head -10  2>&1 | tee -a $LOG > /dev/null
    subtitle "Network Hierarchy Item Counted"
        psql -U qradar -c "select count(*) from network;"  2>&1 | tee -a $LOG > /dev/null
        info "Network Hierarchy Local IP addresses count as other"
            nhlist=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20sourceip%2cNETWORKNAME%28sourceip%29%20from%20events%20where%20%28%20INCIDR%28'10.0.0.0/8'%2c%20sourceip%29%20or%20INCIDR%28'192.168.0.0/16'%2c%20sourceip%29%20or%20INCIDR%28'172.16.0.0/20'%2c%20sourceip%29%29%20and%20NETWORKNAME%28sourceip%29%20%3D%20'other'%20%20group%20by%20sourceip%20order%20by%20sourceip%20LIMIT%2020%20last%2030%20MINUTES" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            nhstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${nhlist}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            while [ true ]
            do
            nhstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${nhlist}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            sleep 5
            echo -e "\n Network Hierarchy Search in $nhstatus mode"
            if [ "$nhstatus" == "COMPLETED" ]
            then
            break
            fi
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${nhlist}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null 
    subtitle "Reference Sets"
         psql -U qradar -c "select id,name,to_timestamp(created_time/1000),timeout_type,time_to_live,current_count from reference_data where current_count is not null order by current_count desc limit 10;" 2>&1 | tee -a $LOG > /dev/null 
    
    subtitle "Event Pipeline ECS-EC-INGRESS"
        cat /var/log/qradar.log | grep "com.q1labs.sem.monitors.SourceMonitor" | grep "Incoming raw event rate" | tail -20 2>&1 | tee -a $LOG > /dev/null
        $JMX  -p 7787 -b "com.eventgnosis:type=EC_Ingress Queues,name=TCP_TO_ECParse" 2>&1 | tee -a $LOG > /dev/null
        info "ECS service status and uptime"
            $SYSCTL status ecs-ec-ingress 2>&1 | tee -a $LOG > /dev/null
        info "EC_Ingress Queues"
            $JMX -p 7787 -b "com.eventgnosis:type=EC_Ingress Queues,name=*" 2>&1 | tee -a $LOG > /dev/null
        info "EC_Ingress Sources"
            $JMX  -p 7787 -b "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=.*Source$" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC-INGRESS Source Monitor"    
            $JMX  -p 7787 -b "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=Source Monitor" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC-INGRESS TCP Syslog"
            $JMX  -p 7787 -b "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=TcpSyslogSource(0.0.0.0/514) Source" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC-INGRESS TcpSyslogProvider0"
            $JMX  -p 7787 -b "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=TcpSyslog(0.0.0.0/514) Source Connections,id=class com.q1labs.semsources.sources.tcpsyslog.TcpSyslogProvider0" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC-INGRESS Syslog Source"
            $JMX  -p 7787 -b "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=Syslog Source" 2>&1 | tee -a $LOG > /dev/null
        $JCTL -u ecs-ec-ingress -r --no-pager >> $LOG > /dev/null
    subtitle "Event Pipeline ECS-EC Statistics"
        info "ECS service status and uptime"
            $SYSCTL status ecs-ec 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC DSM"
            $JMX -p 7777 -b "com.q1labs.sem:application=ecs-ec.ecs-ec,type=filters,name=DSM" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC Parsing General"
            $JMX -p 7777 -b "com.eventgnosis:type=EC Queues,name=Parsing" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC Parsing DSM Normalize"
            $JMX -p 7777 -b "com.eventgnosis:type=EC Queues,name=Parsing/DSM_Normalize" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC Processor"
            $JMX -p 7777 -b "com.eventgnosis:type=EC Queues,name=Processor2" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC ECIngress_via_TCPIP"
            $JMX -p 7777 -b "com.eventgnosis:type=EC Queues,name=Q1From_ECIngress_via_TCPIP" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC TCP_TO_EP EventsPosted==TotalPassed"
            $JMX -p 7777 -b "com.eventgnosis:type=EC Queues,name=TCP_TO_EP" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC TrafficAnalysis1"
            $JMX -p 7777 -b "com.eventgnosis:type=EC Queues,name=TrafficAnalysis1" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC QidMapFactory compare Hits and Misses ratio"
            $JMX -p 7777 -b "com.q1labs.frameworks.cache:application=ecs-ec.ecs-ec,id=UniqueStringCache-QidMapFactory" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC TCP_TO_EP"
            $JMX -p 7777 -b "com.q1labs.frameworks.queue:application=ecs-ec.ecs-ec,id=ecs-ec_EC_TCP_TO_EP" 2>&1 | tee -a $LOG > /dev/null
        info "ECS-EC DSM Extension List"
            $JMX -p 7777 -b | grep "name=DSM Extension" 2>&1 | tee -a $LOG > /dev/null
        info  "Custom Properties Enabled with no restriction"
            psql -t -x -U qradar -c "select propertyname,enabled,regex,devicetypeid,devicetypedescription,qid,username from ariel_property_view where enabled='t' and deprecated='f' and devicetypeid='-1' and database='events';" 2>&1 | tee -a $LOG > /dev/null
        info "How many Custom Property defined by Users"
            psql -U qradar -c "select count(*) from ariel_property_view where enabled='t' and deprecated='f' and username!='admin';" 2>&1 | tee -a $LOG > /dev/null
        info "Custom Property defined for UniversalDSM"
            psql -U qradar -c "select propertyname,deviceid,category,qid,to_timestamp(creationdate/1000),database,regex,username from ariel_property_view where devicetypedescription='Universal DSM';" 2>&1 | tee -a $LOG > /dev/null

        info "journalctl for ECS-EC"
            $JCTL -u ecs-ec -r --no-pager 2>&1 | tee -a $LOG > /dev/null
    subtitle "Event Pipeline ECS-EP"
        info "ECS-EP service status and uptime"
            $SYSCTL status ecs-ep 2>&1 | tee -a $LOG > /dev/null
        info "Analytics Stacks"
            $JMX -p 7799 -b "com.eventgnosis:type=EP Queues,name=AnalyticStack" 2>&1 | tee -a $LOG > /dev/null
        info "Entry Router Stack "
            $JMX -p 7799 -b "com.eventgnosis:type=EP Queues,name=EntryRouterStack" 2>&1 | tee -a $LOG > /dev/null  
        info "NATIVE FROM CRE"
            $JMX -p 7799 -b "com.eventgnosis:type=EP Queues,name=NATIVE_FROM_CRE" 2>&1 | tee -a $LOG > /dev/null
        info "Processors"
            $JMX -p 7799 -b "com.eventgnosis:type=EP Queues,name=Processor*" 2>&1 | tee -a $LOG > /dev/null
        info "Q1From EC vi TCPIP"
            $JMX -p 7799 -b "com.eventgnosis:type=EP Queues,name=Q1From_EC_via_TCPIP" 2>&1 | tee -a $LOG > /dev/null
        info "To findout data nodes connected"
            $JMX -p 7799 -b "com.ibm.si.ariel.dcs.config:application=ecs-ep.ecs-ep,type=DataClusterConfiguration" 2>&1 | tee -a $LOG > /dev/null
        info "Check Event Average Payload and Record Size"
            $JMX -p 7799 -b "com.q1labs.ariel:application=ecs-ep.ecs-ep,type=Database writer,a1=events-2" 2>&1 | tee -a $LOG > /dev/null
        info "Check Flow Average Payload and Record Size"
            $JMX -p 7799 -b "com.q1labs.ariel:application=ecs-ep.ecs-ep,type=Database writer,a1=flows-1" 2>&1 | tee -a $LOG > /dev/null
        info "EPS Long and Short Window"
            $JMX -p 7799 -b "com.q1labs.sem:application=Event Processor,name=EP Monitor" 2>&1 | tee -a $LOG > /dev/null
        info "CRE QueueSize,EventsRoutedToStorageOnStartupCount,EventsSeen"
            $JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=CRE" 2>&1 | tee -a $LOG > /dev/null
        info "journalctl for ECS-EC-Ingress"
            $JCTL -u ecs-ep -r --no-pager >> $LOG > /dev/null
    subtitle "HA Information"
        $MYVER -ha 2>&1 | tee -a $LOG > /dev/null 
        info "HA Information Using Ha Diagnosis"
            HAFILE="$(find /opt/qradar/ -type f -iname "ha_diagnosis.sh"| head -1)"
            $HAFILE -S -s -c 2>&1 | tee -a $LOG > /dev/null
        info "DRBD Health"
            $DRBDO 2>&1 | tee -a $LOG > /dev/null
        info "Crossover status"
            NETTUNEF=$(find /opt/qradar/ -type f -iname "qradar_nettune.pl"| head -1)
            $NETTUNEF  crossover status 2>&1 | tee -a $LOG > /dev/null
    subtitle "File System Information"
        info "Disk Info LSBLK Partitioning"
            $LSBLK 2>&1 | tee -a $LOG > /dev/null
        info "Disk Info BLKID  Partitioning"
            $BLK 2>&1 | tee -a $LOG > /dev/null
        info "Disk Info  Inode Usage"
            $DF -Ti 2>&1 | tee -a $LOG > /dev/null
    subtitle "Backup Status"
        psql -U qradar -c "select host_id,type,to_timestamp(time_initiated/1000) as stime, to_timestamp(time_completed/1000) as etime,initiated_by_user,status from backup where status='SUCCESS' order by stime limit 50" 2>&1 | tee -a $LOG > /dev/null
    subtitle "IOPS Statistics"
        info "Checking write speed. This may take a while"
            $FIO --name=seqwrite --directory=/store --ioengine=libaio --iodepth=1 --rw=write --bs=4k --direct=1 --size=5G --numjobs=1 --runtime=60 --group_reporting 2>&1 | tee -a $LOG  > /dev/null
            $RM /store/seqwrite*
        info "EXTRA INFORMATION: DD check of disks"
            $DD if=/dev/zero of=/store/tempfile bs=1M count=1024 conv=sync 2>&1 | tee -a $LOG  > /dev/null
    info "Checking read speed. This may take a while"
            $FIO --name=seqread --directory=/store --ioengine=libaio --iodepth=1 --rw=read --bs=4k --direct=1 --size=5G --numjobs=1 --runtime=60 --group_reporting 2>&1 | tee -a $LOG  > /dev/null
            $RM /store/seqread*
    info "DD check of disks"
        $DD if=/store/tempfile of=/dev/null bs=1M count=1024 2>&1 | tee -a $LOG  > /dev/null
        rm -f /store/tempfile

#WEB-UI
#RULES
title "WEB UI Information"
    subtitle "Rules"
        info "CRE Failure"
            $JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=CustomRuleReader" 2>&1 | tee -a $LOG > /dev/null
        info "CRE: Failed to read rules"
            crefailedrules=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750107%20LIMIT%2010%20last%205%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            frstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${crefailedrules}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            while [ true ]
            do
            frstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${crefailedrules}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            sleep 5
            if [ "$frstatus" == "COMPLETED" ]
            then
            break
            fi
            echo -e "\n CRE: Failed to read rules Search in $frstatus mode"
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${crefailedrules}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    subtitle "Expensive Custom Rules"
        expensiverules=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750120%20LIMIT%2010%20last%205%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
        erstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${expensiverules}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        while [ true ]
        do
        erstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${expensiverules}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        sleep 5
        if [ "$erstatus" == "COMPLETED" ]
        then
        break
        fi
        echo -e "\n Expensive Custom Rules Search in $erstatus mode"
        done
        $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${expensiverules}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
        echo "Getting ExpensiveCustomRules Information from Logs. This may take a while"
        info "Exception Reading CRE Rules check from logs"
            grep -i "Exception Reading CRE Rules" /var/log/qradar.error  | tail -10 2>&1 | tee -a $LOG > /dev/null
        info "Expensive Custom Rules Based On Average Throughput check from logs"
            grep -i "Expensive Custom Rules Based On Average Throughput" /var/log/qradar.error | tail -10 2>&1 | tee -a $LOG > /dev/null
        info "Custom Rule Engine Error check 1  from logs"
            grep -i "Custom Rule Engine has detected a total of" /var/log/qradar.error | tail -10 2>&1 | tee -a $LOG > /dev/null
        info "Custom Rule Engine Error check 2  from logs"
            grep -i "com.q1labs.semsources.cre.CustomRule: \[ERROR\]" /var/log/qradar.error  | tail -10 2>&1 | tee -a $LOG > /dev/null
        info "Expensive Custom Properties or Custom Properties Disabled"
            expensiveproperties=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750138%20or%20qid%3D38750097%20LIMIT%2010%20last%205%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            eprostatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${expensiveproperties}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            while [ true ]
            do
            eprostatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${expensiveproperties}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            sleep 5
            if [ "$eprostatus" == "COMPLETED" ]
            then
            break
            fi
            echo -e "\n Expensive Custom Properties Search in $eprostatus mode"
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${expensiveproperties}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    subtitle "Offenses"
        info "Offense Type Analysis NumberEventsSentToMPC/EventsAnalyzed ratio"
            $JMX -p 7799 -b "com.q1labs.sem:application=ecs-ep.ecs-ep,type=filters,name=Offense Type Analysis" 2>&1 | tee -a $LOG > /dev/null
        info "Top offenses name. This may take a while"
            $CURL -S -s -X GET -H 'Version: 16.0' -H 'Accept: application/json' -H "SEC:$API_KEY" -H "Range: items=0-10" "https://${IPCon}/api/health_data/top_offenses"  | $JQ "." 2>&1 | tee -a $LOG > /dev/null
        info "Rules Offense Contributions Top 30"
            $CURL -k -S -s -X GET -H 'Range: items=0-30' -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY" "https://${IPCon}/api/analytics/rules_offense_contributions?fields=rule_name%2Cevent_count&sort=-event_count" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    subtitle "Searches"
        info "Finding searches which return more than 200MB data"
            find /transient -xdev -type f -size +200M | xargs ls -lh | tail -10 2>&1 | tee -a $LOG > /dev/null
        info "Finding Most User who perform search"
            searchesbyuser=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20qidname%28qid%29%20as%20'Event'%2c%20count%28%2A%29%20as%20'Count'%2c%20username%20as%20'Username'%2c%20dateformat%28devicetime%2c'dd%2DMM%2DYYYY%20HH:mm:ss'%29%20as%20Time%2c%20utf8%28payload%29%20as%20'Payload'%20from%20events%20where%20%20LOGSOURCENAME%28logsourceid%29%20like%20'SIM%20Audit%25'%20and%20%28username%20not%20like%20%27ariel_client%25'%29%20and%20%28QIDNAME%28qid%29%20=%20'Search%20Executed'%29%20Group%20by%20Username%20order%20by%20'Time'%20DESC%20last%203%20days" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            sbystatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${searchesbyuser}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            while [ true ]
            do
            sbystatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${searchesbyuser}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            sleep 5
            if [ "$sbystatus" == "COMPLETED" ]
            then
            break
            fi
            echo -e "\n Most user performing searches Search in $sbystatus mode"
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${searchesbyuser}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
        info "Search Executed Number"
            $JMX -p 7782 -b "com.q1labs.ariel:application=ariel_proxy.ariel_proxy_server,type=Query server,a1=Cursors" -a RunningQueries -a SearchCount 2>&1 | tee -a $LOG > /dev/null
        info "Parallel Execution on Search"
            $JMX -p 7782 -b "com.q1labs.ariel:application=ariel_proxy.ariel_proxy_server,type=Query server,a1=Parallel execution"
#Indexes 
    subtitle "Indexes"
        info "Check Index Managent from GUI"
#
#Global Views 
    subtitle "Global Views"
        $GVSTAT -s 2>&1 | tee -a $LOG > /dev/null
#
#Assets 
    subtitle "Assets"
        info "Log Source Type used for asset creation"
            logsourcehelpasset=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20LOGSOURCETYPENAME%28devicetype%29%20as%20'LogSourceType'%20from%20events%20where%20%20hasidentity%3Dtrue%20group%20by%20LogSourceType%20order%20by%20LogSourceType%20last%201%20days" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
            lshacstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${logsourcehelpasset}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            while [ true ]
            do
            lshacstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${logsourcehelpasset}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
            sleep 5
            if [ "$lshacstatus" == "COMPLETED" ]
            then
            break
            fi
            echo -e "\n Asset Creation by Log Source Type Search in $lshacstatus mode"
            done
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${logsourcehelpasset}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
#
#Event & Flow Retention
    subtitle "Event Retention"
        psql -U qradar -c "select db,bucket_id,name,records,to_timestamp(mtime/1000),tenant_id from retention where enabled='t' order by db,bucket_id;" 2>&1 | tee -a $LOG > /dev/null
#
#Applications
    subtitle "Applications"
        psql -U qradar -c "select id,name,image_repo,installed_by,installed_on,status,errors,memory,cpu_share,ootb_install,multitenancy_safe,single_instance_only,image from installed_application;" 2>&1 | tee -a $LOG > /dev/null
        info "EXTRA INFORMATION: Application JSON Format"
            $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json'  "https://$IPCon/api/gui_app_framework/applications?fields=application_state%28application_id%2Cstatus%2Cmemory%29%2Cmanifest%28version%2Cname%29" -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
#
#LOG SOURCES
title "Log Sources" 
    subtitle "Log Sources Unparsed Events, Droped Events, Unknown Log Sources"
    info "Log Sources Dropped Events"
        droppedevents=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750060%20LIMIT%2010%20last%2015%30DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
        destatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${droppedevents}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        while [ true ]
        do
        destatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${droppedevents}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        sleep 5
        if [ "$destatus" == "COMPLETED" ]
        then
        break
        fi
        echo -e "\n Dropped Events Search in $destatus mode"
        done
        $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${droppedevents}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    info "Unknown Long Sources"
        ulogsource=$($CURL -k -S -s --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20utf8%28payload%29%20from%20events%20where%20qid%3D38750007%20LIMIT%2010%20last%201%20DAYS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
        ulstatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${ulogsource}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        while [ true ]
        do
        ulstatus="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${ulogsource}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        echo "Unknown Long Sources Search in $ulstatus mode"
        sleep 5
        if [ "$ulstatus" == "COMPLETED" ]
        then
        break
        fi
        secs=$((1 * 5))
        while [ $secs -gt 0 ]
        do
           echo -ne "Unknown Long Sources Search in $ulstatus mode $secs second to next check\r"
           sleep 1
           : $((secs--))
           done
        done
        $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${ulogsource}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    info "Unparsed Logs"
        unparsed=$($CURL -k -S -s --location --request POST "https://$IPCon/api/ariel/searches?query_expression=select%20LONG%28count%28*%29%29%20as%20Total%20%2cLOGSOURCENAME%28logsourceid%29%20as%20LST%20from%20events%20where%20isunparsed%3DTrue%20group%20by%20LST%20order%20by%20Total%20ASC%20last%206%20HOURS" -H "Version: $API_VERSION" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.search_id')
        upestatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${unparsed}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        while [ true ]
        do
        status="$($CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${unparsed}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
        sleep 3
        if [ "$upestatus" == "COMPLETED" ]
        then
        break
        fi
        secs=$((1 * 5))
                while [ $secs -gt 0 ]
                do
                echo -ne "Unparsed Log Search in $upestatus mode $secs second to next check\r"
                upestatus="$($CURL -k -S -s -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${unparsed}" -H 'Accept: application/json' -H "SEC:$API_KEY"| jq -r '.status')"
                sleep 1
                : $((secs--))
                done
        done
        $CURL -k -s -S -X GET -H "Version: $API_VERSION" -H 'Accept: application/json' "https://$IPCon/api/ariel/searches/${unparsed}/results" -H 'Accept: application/json' -H "SEC:$API_KEY" | $JQ "." 2>&1 | tee -a $LOG > /dev/null
    subtitle "Log Sources (Enabled One)"
        psql -U qradar -c "select sd.id,sd.store_event_payload,eps60s as EPS60s,logonly,coalesce_events as Coalesced,to_timestamp(timestamp_last_seen/1000) as LastSeen,peakeps60s as PeakEPS,timestamp_peakeps60s as TimePeakEPS,devicetypename from sensordevice as sd left join sensordevicetype as sdt on sdt.id=sd.devicetypeid where deviceenabled='t' order by devicetypename,TimePeakEPS;" 2>&1 | tee -a $LOG > /dev/null
    subtitle "Log Source Extention"
        psql -U qradar -c "select id,name,enabled,use_condition from device_ext where enabled='t';" 2>&1 | tee -a $LOG > /dev/null
        info "Extensions Based on Average Throughput in the last 60 seconds on old files"
            zgrep -i "Extensions Based on Average Throughput in the last 60 seconds" /var/log/qradar.old/qradar.log.* | tail -30 2>&1 | tee -a $LOG > /dev/null
        info "Extensions Based on Average Throughput in the last 60 seconds on log"
            grep -i "Extensions Based on Average Throughput in the last 60 seconds" /var/log/qradar.log | tail -30 2>&1 | tee -a $LOG > /dev/null
  subtitle "Parsing"
        $JMX -p 7777 -b "com.q1labs.sem:application=ecs-ec.ecs-ec,type=filters,name=DSM,id=*" --json | jq -r '.' | grep -P "\"EventsReceived\":\s+\"\d{5}" -A6 -B4  2>&1 | tee -a $LOG > /dev/null
    subtitle "Wincollect Agents and Dependent Log Source Analysis"
        psql -U qradar -c "select hostname,acs.description,deployed from ale_client as ac left join ale_client_status as acs on acs.id=ac.status where enabled='t';" 2>&1 | tee -a $LOG > /dev/null
    subtitle "7.5.  Wincolect Agent and Dependent Log Source Analysis"
        $WINCOLCHK -l 2>&1 | tee -a $LOG > /dev/null
    subtitle "RPM"
        cat /var/log/rpmdb.log | egrep -v '^[[:space:]]+1'  2>&1 | tee -a $LOG > /dev/null
        info "Sanity: Should be not any result"
            $SCHECK  2>&1 | tee -a $LOG > /dev/null
        info "Protocol Version"
            rpm -qa | grep PROTOCOL 2>&1 | tee -a $LOG > /dev/null    
        info "DSM Version"
            rpm -qa | grep DSM 2>&1 | tee -a $LOG > /dev/null
#
#PSQL DB Health
title "PSQL DB Health"
    psql -U qradar -c "select * from q_table_size order by mb desc limit 10"  2>&1 | tee -a $LOG > /dev/null

#
#Managed Host Part From Console - Copying&Running Managed Host Script
##I HAVE TO CHECK THIS PART if [ $mhcount -gt 1 ]
##I HAVE TO CHECK THIS PART        then
##I HAVE TO CHECK THIS PART        title "Managed Host Part Running"
##I HAVE TO CHECK THIS PART        subtitle "Sending ManagedHost Script to Managed Hosts"
##I HAVE TO CHECK THIS PART            /opt/qradar/support/all_servers.sh -p /root/managedhost-hc.sh -r /root
##I HAVE TO CHECK THIS PART        subtitle "Starting script on Managed Host. This may take a while, approximately 10 minutes or more"
##I HAVE TO CHECK THIS PART        if [ -z $SCRT ]
##I HAVE TO CHECK THIS PART        then
##I HAVE TO CHECK THIS PART            /opt/qradar/support/all_servers.sh "$SCRT new -s MHHCS -d \"bash /root/managedhost-hc.sh -r\""
##I HAVE TO CHECK THIS PART        else 
##I HAVE TO CHECK THIS PART            /opt/qradar/support/all_servers.sh "$SCRS -S MHHCS 
##I HAVE TO CHECK THIS PART
##I HAVE TO CHECK THIS PART            mhall=$(echo ${#MyMHs[@]})
##I HAVE TO CHECK THIS PART            result=$(/opt/qradar/support/all_servers.sh -t 1 "$SCR list-sesion |grep MHHCS" | grep MHHCS| wc -l)
##I HAVE TO CHECK THIS PART            while [ true ]
##I HAVE TO CHECK THIS PART            do
##I HAVE TO CHECK THIS PART                    result=$(/opt/qradar/support/all_servers.sh -t 1 "$SCR list-sessions |grep  MHHCS" | grep MHHCS| wc -l)
##I HAVE TO CHECK THIS PART                    if [ $result -eq 0 ]
##I HAVE TO CHECK THIS PART                    then
##I HAVE TO CHECK THIS PART                            clear
##I HAVE TO CHECK THIS PART                            echo "Done"
##I HAVE TO CHECK THIS PART                            break
##I HAVE TO CHECK THIS PART                    else
##I HAVE TO CHECK THIS PART                    secs=$((1 * 60))
##I HAVE TO CHECK THIS PART                    while [ $secs -gt 0 ]
##I HAVE TO CHECK THIS PART                    do
##I HAVE TO CHECK THIS PART                    clear
##I HAVE TO CHECK THIS PART                            echo -ne " Script running on $result server. We will check in 1 minutes interval to finish. $secs second to next check\r"
##I HAVE TO CHECK THIS PART                            sleep 1
##I HAVE TO CHECK THIS PART                            : $((secs--))
##I HAVE TO CHECK THIS PART                    done
##I HAVE TO CHECK THIS PART            
##I HAVE TO CHECK THIS PART                    fi
##I HAVE TO CHECK THIS PART            done
##I HAVE TO CHECK THIS PARTfi
#CLEARING SECTION AT END
##I HAVE TO CHECK THIS PARTtitle "Clearing section"
##I HAVE TO CHECK THIS PARTsubtitle "Deleting unneccessary files"
##I HAVE TO CHECK THIS PART/opt/qradar/support/all_servers.sh -t 1 "rm -f /root/managedhost-hc.sh" >> /dev/null
title "Script Done. You can check the results in $LOG file"
}

# Read in command line arguments
while getopts "hvr" OPT
do
        case $OPT in
        h)
        usage
            exit 0
            ;;
        v)
            version
            exit 0
            ;;
        r)
            runscript
            ;;
        *)
            usage
            exit 0
            ;;
esac
done
