#!/usr/bin/env bash
#to use this file; 
##type at the begininig of file
# . qradar_functions.sh --source-only
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
[ -f /opt/qradar/support/rpm_db_sanity_check.sh ] && SCHECK=" /opt/qradar/support/rpm_db_sanity_check.sh" || qct  /opt/qradar/support/rpm_db_sanity_check.sh

#FUNCTIONS
REV="1.2"
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
        echo "This is not console please do not run file. Exiting"
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

function ct(){
    if [ ! -f $1 ]
    then
        echo "Command $1 not found existing " 2>&1 | tee -a $LOG 
        exit 0
    fi
}

function qct(){
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
function managedhostlist() {
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
        export ITAIO="yesaio"
        echo "This is AIO environment" 2>&1 | tee -a $LOG > /dev/null
    fi
}
main() {
    echo "This script contains functions. Do not run directly."
    
}

if [ "${1}" != "--source-only" ]; then
    main "${@}"
fi

#VARIABLES
BLK=$(which blkid) && ct $BLK
CURL=$(which curl) && ct $CURL
CP=$(which cp) && ct $CP
DD=$(which dd) && ct $DD
DF=$(which df) && ct $DF
DMESG=$(which dmesg) && ct $DMESG
DMI=$(which dmidecode) && ct $DMI
DRBDO=$(which drbd-overview) && ct $DRBDO
ETHTOOL=$(which ethtool) && ct $ETHTOOL
EXP=$(which expect) && ct $EXP
FIO=$(which fio) && ct $FIO
FIND=$(which find) && ct $FIND
HNAME=$(which hostnamectl) && ct $HNAME
HSTN=$(which hostname) && ct $HSTN
IFC=$(which ifconfig) && ct $IFC
IOT=$(which iotop) && ct $IOT
IPC=$(which ip) && ct $IPC
JCTL=$(which journalctl) && ct $JCTL
JQ=$(which jq) && ct $JQ
LSBLK=$(which lsblk) && ct $LSBLK
LSCPU=$(which lscpu) && ct $LSCPU
MKDIR=$(which mkdir) && ct $MKDIR
RM=$(which rm) && ct $RM
SCRIPT=$(readlink -f $0)
SCRS=$(which screen) && ct $SCRS
SCRT=$(which tmux) && ct $SCRT
SSH=$(which ssh) && ct $SSH
SYSCTL=$(which systemctl) && ct $SYSCTL
TOP=$(which top) && ct $TOP
TRUNCATE=$(which truncate) && ct $TRUNCATE
UPT=$(which uptime) && ct $UPT
VMS=$(which vmstat) && ct $VMS
XFS=$(which xfs_info) && ct $XFS
