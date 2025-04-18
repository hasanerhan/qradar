#!/usr/bin/env bash
. qradar_functions.sh --source-only
# AUTHOR      : Hasan Erhan AYDINOGLU 
# EMAIL       : hasan.erhan.aydinoglu@ibm.com
# DATE        : 2025/03/14
# UPDATE      :  
# VERSION     : Check $REV variable
# DESCRIPTION : Transfer files to measure bandwith to MH and  ping test to MH.  
#             :  
# CHANGELOG   :
# 
# TODO        : 
#
REV="1.0"
function version {
  clear
  echo -e "VERSION: $REV"
  exit 0
 }
if [ "$1" == "-v" ]
then
version
fi
# LET'S GO
clear
TSMP="$(date +"%b %d %H:%m:%S %Y")"
MYH=$(hostname -s)
LOG="/storetmp/upgradecheck/${MYH}_logforupgrade_check.log"
#PING TEST
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
 printf "|%3s| Ping result for %s is greater than %s ms\n" "ERR" "$mymh" "$T1" 2>&1 | tee -a $LOG
else
 printf "|%3s| Ping result for %s is %s ms\n" "OK" "$mymh" "$T1" 2>&1 | tee -a $LOG
fi
done
#NETWORK TEST
truncate -s 1G /root/test.txt >/dev/null # Create file
for mymh in ${MyMHs[@]}
do 
up_speed=$(scp -v /root/test.txt $mymh:/root/ 2>&1 | grep "Bytes per second" | sed "s/^[^0-9]*\([0-9.]*\)[^0-9]*\([0-9.]*\).*$/\1/g")
up_speed=$(echo "$up_speed/1000000"|bc)
if [ $up_speed -lt 100 ]
then
  printf "|%3s| Upload speed is measured is not enough for $mymh It is %s MB/s\n" "ERR" "$up_speed" 2>&1 | tee -a $LOG
else
  printf "|%3s| Upload speed is measured is enough for $mymh It is %s MB/s\n" "OK" "$up_speed" 2>&1 | tee -a $LOG
fi
  done
#Delete File from Managed hosts
/opt/qradar/support/all_servers.sh -C "rm -f /root/test.txt" >/dev/null # Deleting files which created

for mymh in ${MyMHs[@]}
do 
for i in $(seq 1 10)
do ssh $mymh uname -a > /dev/null
done
if [ $i -eq 10 ]
  then
    printf "|%3s| Total ssh count for $mymh is $i\n" "OK"  2>&1 | tee -a $LOG
  else 
    printf "|%3s| Total ssh count for $mymh is $i Should be 10\n" "ERR"  2>&1 | tee -a $LOG
  fi
done

