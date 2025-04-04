#!/usr/bin/env bash
. qradar_functions.sh --source-only
# AUTHOR      : Hasan Erhan AYDINOGLU 
# EMAIL       : hasan.erhan.aydinoglu@ibm.com 
# START DATE  : 2024/03/05
# UPDATE DATE : 
# VERSION     : Check REV variable
# DESCRIPTION : This script working on Console and managed host with using all_server.sh script to check Upgrade APAR and Known Issues 
# CHANGELOG   : v1.0 First Publication
#TODO:
#Functions
clear
#VARIABLES
TSMP="$(date +"%b %d %H:%m:%S %Y")"
MYH=$(hostname -s)
LOG="/storetmp/upgradecheck/${MYH}_logforupgrade_check.log"
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
if [ 5120 -lt $xtmp  ]
then
   echo -e "$TSMP [OK] tmp is enough storage for upgrade" |tee -a $LOG  >/dev/null
else 
   echo -e "$TSMP [ERR] tmp is not enough storage for upgrade" |tee -a $LOG  >/dev/null
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
ls -1 /opt/ibm/java-x86_64-80/jre/lib/security/*.jar| grep -ie local_policy -ie US_export_policy >/dev/null
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
if [ $MYAUV = "9.9" ] || [ $MYAUV = "9.10" ]
then
   echo -e "$TSMP [ERR] can experience connection issues due to deprecated GPG keys or the au-cert.pem file is an old version. Do not upgrade" |tee -a $LOG  >/dev/null
else
   echo -e "$TSMP [OK] no auto update issue detected. You can upgrade" |tee -a $LOG  >/dev/null
fi
#
#Move script to all appliances
if [ "$ITAIO" == "yesaio" ]
then
   if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
   then
   echo "$TSMP Script copying to managed hosts" 2>&1 | tee -a $LOG
   /opt/qradar/support/all_servers.sh -p $SCRIPT -r /root
   fi
   if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
   then
      echo "$TSMP Screen creating and running on managed hosts" 2>&1 | tee -a $LOG
   fi
   if [ -z $SCRT ]
   then
      /opt/qradar/support/all_servers.sh "$SCRT new -s MHC -d \"bash /root/${SCRIPT} -r\""  >/dev/null
   else
      /opt/qradar/support/all_servers.sh "$SCRS -S MHC -dm"   >/dev/null
      /opt/qradar/support/all_servers.sh "$SCRS -S MHC -X stuff 'bash /root/${SCRIPT};exit\r'"   >/dev/null
   
   fi
   if [ $(cat /opt/qradar/conf/capabilities/hostcapabilities.xml  | grep isConsole | awk -F '"' {'print $2'}) = "true" ]
   then
   
   if [ -z $SCRT ]
   then
      result=$(/opt/qradar/support/all_servers.sh -t 1 "$SCRT ls |grep MHC" | grep MHC| wc -l)
      
   else
      result=$(/opt/qradar/support/all_servers.sh -t 1 "$SCRS -list |grep MHC" | grep MHC| wc -l)
   fi
   
         while [ true ]
         do
   
            if [ -z $SCRT ]
            then 
               result=$(/opt/qradar/support/all_servers.sh -t 1 "$SCRT ls |grep MHC" | grep MHC| wc -l)
            else
               result=$(/opt/qradar/support/all_servers.sh -t 1 "$SCRS -list |grep  MHC" | grep MHC| wc -l)
            fi
           if [ $result -eq 0 ]
           then
                   echo "Done" 2>&1 | tee -a $LOG 
                   break
           else
           secs=$((1 * 60))
           while [ $secs -gt 0 ]
           do
           
                   echo -ne " Script running on $result server. We will check in 1 minutes interval to finish. $secs second to next check\r"
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
   for mymh in ${MyMHs[@]}
      do 
         echo "Getting logs from managed hosts" 2>&1  | tee -a $LOG
         scp $mymh:/storetmp/upgradecheck/*logforupgrade_check.log /storetmp/upgradecheck/   >/dev/null
   done
   fi
#
#Ping and Bandwith Check
echo "$TSMP Ping and Bandwith Check for managed hosts" 2>&1 | tee -a $LOG
bash /root/measure_bw_and_ping.sh
fi
echo "DONE"
echo "You can find logs in $LOG"
exit 0