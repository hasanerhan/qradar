#!/usr/bin/env bash
#HEA
# AUTHOR      : Hasan Erhan AYDINOGLU 
# EMAIL       : hasan.erhan.aydinoglu@ibm.com 
# START DATE  : 2024/03/05
# UPDATE DATE : 
# VERSION     : Check REV variable
# DESCRIPTION : This script working on Console and managed host with using all_server.sh script to check Upgrade APAR and Known Issues 
# CHANGELOG   : v1.0 First Publication
#TODO:
#
#VARIABLES
clear
REV="1.3"
IPCon="10.0.8.230"
MYH=$(hostname -s)
LOG="/storetmp/upgradecheck/${MYH}_logforupgrade_check.log"
DD=$(which dd)
SYSCTL=$(which systemctl)
SCRT=$(hash tmux 2>/dev/null;echo $?)
SCRS=$(hash screen 2>/dev/null;echo $?)
FIND=$(which find)
MKDIR=$(which mkdir)
SYSCTL=$(which sysctl)
RM=$(which rm)
EXP=$(which expect)
CP=$(which cp)
SSH=$(which ssh)
DMESG=$(which dmesg)
FIO=$(which fio)
LSBLK=$(which lsblk)
BLK=$(which blkid)
DF=$(which df)
LSCPU=$(which lscpu)
UPT=$(which uptime)
VMS=$(which vmstat)
HNAME=$(which hostnamectl)
HSTN=$(which hostname)
IPC=$(which ip)
TOP=$(which top)
XFS=$(which xfs_info)
IOT=$(which iotop)
JQ=$(which jq)
IFC=$(which ifconfig)
CURL=$(which curl)
DMI=$(which dmidecode)
JCTL=$(which journalctl)
ETHTOOL=$(which ethtool)
TRUNCATE=$(which truncate)
DRBDO=$(which drbd-overview)
SCRIPT=$(echo $0 | awk -F\/ '{print $NF}')
TSMP="$(date +"%b %d %H:%m:%S %Y")"
#
#FUNCTIONS
function qct(){
    if [ ! -f $1 ]
    then
        echo "Command/Path $1 not found"  2>&1 | tee -a $LOG
    fi
}
function version {
  clear
  echo -e "VERSION: $REV"
  exit 0
 }
if [ "$1" == "-v" ]
then
version
fi
function isconsole(){
    if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) != "true" ]
    then
        echo "This is not console please run managedhost-hc.sh file. Exiting"
        exit 0
    else
        if [ "$($MYVER -cip)" == "$IPCon" ]
        then
          echo "IPCon defined in script matched with IP address of console. Continuing"
        else
         echo "IPCon defined in script do not matched with IP address of console. Exiting"
         exit 0
      fi
    fi
}
function managedhostlist() {
    if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
    then
        mhcount=$(psql -U qradar -t -c "select count(ip) from managedhost where isconsole='f' and status='Active'")
        if [ $mhcount -gt 1 ]
        then
            ITAIO="noaio"
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
            ITAIO="yesaio" 
            echo "This is AIO environment" 2>&1 | tee -a $LOG > /dev/null
        fi
    fi
}
#
#QRADAR COMMANDS
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
[ -f /opt/qradar/support/rpm_db_sanity_check.sh ] && SCHECK=" /opt/qradar/support/rpm_db_sanity_check.sh" || qct  /opt/qradar/support/rpm_db_sanity_check.sh
#
#MAIN
mkdir -p /storetmp/upgradecheck/
touch $LOG
cat /dev/null > $LOG
#
#Storetmp usage
echo "$TSMP Check storetmp disk usage should be minimum 10G" 2>&1 |tee -a $LOG
xstoretmp=$($DF -m --output=avail /storetmp | tail -1 | sed 's/ //g')
if [ 10240 -lt $xstoretmp  ]
then
   echo -e "$TSMP [OK] storetmp is enough storetmp for upgrade" |tee -a $LOG >/dev/null
else 
   echo -e "$TSMP [ERR] storetmp is not enough storetmp for upgrade" |tee -a $LOG  >/dev/null
fi
#
#tmp usage
echo "$TSMP Check tmp disk usage should be minimum 5GB" 2>&1 |tee -a $LOG
xtmp=$(df -m --output=avail /tmp | tail -1 | sed 's/ //g')
xstmp=$(df -m --output=avail /storetmp | tail -1 | sed 's/ //g')
xstra=$(df -m --output=avail /store/transient | tail -1 | sed 's/ //g')
if [ 5120 -lt $xtmp  ] && [ 5120 -lt $xstmp ] &&  [ 5120 -lt $xstra ] 
then
   echo -e "$TSMP [OK] tmp or storetmp or store/transient  is enough storage for upgrade" |tee -a $LOG  >/dev/null
else 
   echo -e "$TSMP [ERR] tmp or storetmp or store/transient  is not enough storage for upgrade" |tee -a $LOG  >/dev/null
fi
#
#LUKS
echo "$TSMP Check LUKS encryption " 2>&1 |tee -a $LOG
$LSBLK -o NAME,FSTYPE,TYPE,MOUNTPOINT | grep crypt   >/dev/null
RET=$?
if [ $RET -eq 0 ]
then
   echo -e "$TSMP [ERR] LUKS encryption detected. You can not upgrade" |tee -a $LOG >/dev/null
else
   echo -e "$TSMP [OK] LUKS encryption not detected. You can upgrade" |tee -a $LOG >/dev/null   
fi
#
#xfs_info
if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
then
   echo "$TSMP Check Docker issue"  2>&1 |tee -a $LOG
   xfs_info /store | grep ftype=0
   RET=$?
   if [ $RET -eq 0 ]
   then
      echo -e "$TSMP [ERR] XFS for store is not suaitable for upgrade" |tee -a $LOG  >/dev/null
   else
      echo -e "$TSMP [OK] XFS for store is suitable for upgrade." |tee -a $LOG  >/dev/null      
   fi
   xfs_info /storetmp | grep ftype=0
   RETx=$?
   if [ $RETx -eq 0 ]
   then
      echo -e "$TSMP [ERR] XFS for storetmp is not suaitable for upgrade" |tee -a $LOG  >/dev/null
   else
      echo -e "$TSMP [OK] XFS for storetmp is suitable for upgrade." |tee -a $LOG   >/dev/null     
   fi
fi
#
#IJ38233
echo "$TSMP Check IJ38233:"  2>&1 |tee -a $LOG  
#https://www.ibm.com/mysupport/s/defect/aCI3p000000Ch0w/dt125259?language=en_US
#UNRESTRICTED JCE JAR FILES
ls -1 /opt/ibm/java-x86_64-80/jre/lib/security/*.jar| grep -ie local_policy -ie US_export_policy 2>/dev/null
HCUJ=$?
if [ $HCUJ -eq 0 ]
 then
    echo -e "$TSMP [ERR] HOSTCONTEXT issues detected. Do not upgrade." |tee -a $LOG  >/dev/null
else
   echo -e "$TSMP [OK] NO HOSTCONTEXT issues detected. You can upgrade"  |tee -a $LOG  >/dev/null
fi
#
#AutoUpdate
echo "$TSMP Check Auto update version"  2>&1 |tee -a $LOG
MYAUV="$(/opt/qradar/bin/UpdateConfs.pl -v)"
if [ "$MYAUV" = "9.9" ] || [ "$MYAUV" = "9.10" ]
then
   echo -e "$TSMP [ERR] can experience connection issues due to deprecated GPG keys or the au-cert.pem file is an old version. Do not upgrade" |tee -a $LOG  >/dev/null
else
   echo -e "$TSMP [OK] no auto update issue detected. You can upgrade" |tee -a $LOG  >/dev/null
fi
#
#Move script to all appliances
managedhostlist
if [ "$ITAIO" == "noaio" ]
then
   if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
   then
   echo "$TSMP Script copying to managed hosts" 2>&1 | tee -a $LOG
   /opt/qradar/support/all_servers.sh -t 1 -p $SCRIPT -r /root
   fi
   if [ "$(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'})" = "true" ]
   then
      echo "$TSMP Screen creating and running on managed hosts" 2>&1 | tee -a $LOG
   fi
   if [ $SCRT -eq 0 ]
   then
      /opt/qradar/support/all_servers.sh "$(which tmux) new -s MHC -d 'bash /root/${SCRIPT} \r'"  >/dev/null
   else
      /opt/qradar/support/all_servers.sh "$(which screen) -S MHC -dm"   >/dev/null
      /opt/qradar/support/all_servers.sh "$(which screen) -S MHC -X stuff 'bash /root/${SCRIPT};exit\r'"   >/dev/null
   
   fi
fi
   if [ "$(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'})" = "true" ]
   then
   
   if [ $SCRT -eq 0 ]
   then
      result=$(/opt/qradar/support/all_servers.sh -t 1 "$(which tmux) ls |grep MHC" | grep MHC| wc -l)
      
   else
      result=$(/opt/qradar/support/all_servers.sh -t 1 "$(which screen) -list |grep MHC" | grep MHC| wc -l)
   fi
   
         while [ true ]
         do
   
            if [ $SCRT -eq 0 ]
            then 
               result=$(/opt/qradar/support/all_servers.sh -t 1 "$(which tmux) ls |grep MHC" | grep MHC| wc -l)
            else
               result=$(/opt/qradar/support/all_servers.sh -t 1 "$(which screen) -list |grep  MHC" | grep MHC| wc -l)
            fi
           if [ $result -eq 0 ]
           then
                   echo "Screen created and run" 2>&1 | tee -a $LOG 
                   break
           else
           secs=$((1 * 10))
           while [ $secs -gt 0 ]
           do
                   echo -ne " Script running on $result server. We will check in 10 second interval to finish. $secs second to next check\r"
                   sleep 1
                   : $((secs--))
           done
   
           fi
         done
   fi

   #
   #Getting logs
if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
then
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

fi
    if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
   then
      echo "Getting logs from managed hosts" 2>&1  | tee -a $LOG
     for mh in ${MyMHs[@]};
      do 
        echo "$mh x"
        scp $mh:/storetmp/upgradecheck/*logforupgrade_check.log /storetmp/upgradecheck/
   done
   fi
#
#PING and NETWORK TEST
if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
then
    for mymh in ${MyMHs[@]}
    do 
      T=$(ping -W 1 -c 4 -n $mymh | tail -1 | cut -d " " -f 4 | cut -d "/" -f 2)
      if [ x$T = x ]
      then
        T=1000
      else
      T1=$(printf '%.0f' $T)
    fi
    if [ $T1 -gt 10 ]
    then
     printf "|%3s| Ping result for %s is greater than %s ms\n" "WRN" "$mymh" "$T1" 2>&1 | tee -a $LOG
    else
     printf "|%3s| Ping result for %s is %s ms\n" "OK" "$mymh" "$T1" 2>&1 | tee -a $LOG
    fi
    done
fi
#NETWORK TEST
if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
then
    truncate -s 1G /root/test.txt >/dev/null # Create file
    for mymh in ${MyMHs[@]}
    do 
    up_speed=$(scp -v /root/test.txt $mymh:/root/ 2>&1 | grep "Bytes per second" | sed "s/^[^0-9]*\([0-9.]*\)[^0-9]*\([0-9.]*\).*$/\1/g")
    up_speed=$(echo "$up_speed/1000000"|bc)
    if [ $up_speed -lt 100 ]
    then
      printf "|%3s| Upload speed is measured is not enough for $mymh It is %s MB/s\n" "WRN" "$up_speed" 2>&1 | tee -a $LOG
    else
      printf "|%3s| Upload speed is measured is enough for $mymh It is %s MB/s\n" "OK" "$up_speed" 2>&1 | tee -a $LOG
    fi
      done
fi
#Delete File from Managed hosts
if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
then
    /opt/qradar/support/all_servers.sh -C "rm -f /root/test.txt" >/dev/null # Deleting files which created

    for mymh in ${MyMHs[@]}
    do 
    for i in $(seq 1 10)
    do ssh $mymh uname -a > /dev/null
    done
    if [ $i -eq 10 ]
      then
        printf "|%3s| Total ssh count for $mymh is $i / 10\n" "OK"  2>&1 | tee -a $LOG
      else 
        printf "|%3s| Total ssh count for $mymh is $i Should be 10\n" "ERR"  2>&1 | tee -a $LOG
      fi
    done
fi
/opt/qradar/support/all_servers.sh -t 1 "rm -rf /storetmp/upgradecheck"
/opt/qradar/support/all_servers.sh -t 1 "rm -rf /root/${SCRIPT}"
