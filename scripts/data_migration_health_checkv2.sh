#!/usr/bin/env bash
# AUTHOR      	: Hasan Erhan AYDINOGLU 
# EMAIL       	: hasanerhan@hasanerhan.com 
# DATE      	: 2023/02/26
# UPDATE    	:  
# VERSION     	: v.0.1
# DESCRIPTION 	: Bu script data node degisimi(replacement) oncesinde her iki data node 
#                 sunucusununda da iops,ram,cpu,disk failure vb. hataların tespiti için 
#.                yazılmistir.           
# CHANGELOG   	: 
# TODO		: 

#VARIABLES
DEST=/root/MigrationHealthCheck
DD=$(which dd)
MKDIR=$(which mkdir)
SYSCTL=$(which sysctl)
DMI=$(which dmidecode)
RM=$(which rm)
CP=$(which cp)
LOG=${DEST}/$(hostname)_migrationcheck.log
LSBLK=$(which lsblk)
DF=$(which df)
LSCPU=$(which lscpu)
SCRIPT=$(echo $0 | awk -F\/ '{print $NF}')
REV="0.1"

#Clearing section
$RM -rf $DEST


function version {
	clear
        echo -e "\tVERSION:$SCRIPT $REV"
        echo -e "\tAUTHOR : Hasan Erhan AYDINOGLU"
	echo -e "\tEMAIL  : hasan.erhan.aydinoglu@ibm.com"
}

function title {
	for i in {1..40}; do echo -n "=" | tee -a $LOG >> /dev/tty;done
	echo -e "\n## $1" | tee -a $LOG >> /dev/tty
	for i in {1..40}; do echo -n "=" | tee -a $LOG >> /dev/tty;done
	echo -e "\n"| tee -a $LOG >> /dev/tty
	}

function usage {
	clear
	version
	echo "Usage:"
    	echo -e "\t-r :: Run the script"
    	echo -e "\t-v :: Script Version"
	echo -e "\t-h :: Help (This information)"
	echo
}
# Show usage if there were no arguments passed
if [[ $@ =~ --help || $# -eq 0 ]]
then
        usage
        exit 0
fi

function storevolume {
	#Is it part or lvm
	lvs --noheadings -o lv_name | sed 's/ //g'| grep -e ^store$
	if [ $? -eq 0 ];
	then
	 title "Store is lvm"
	 getvolume="$(lvs -o lv_full_name,devices|grep -e '/store ' |awk {'print $2'} |cut -d\/ -f3|cut -d\( -f1)"
	else
	 title "Store is not lvm"
	 getvolume="$(lsblk -r| grep -e '/store$'| cut -d " " -f 1)"
   	fi
	}

function runscript {
	mkdir -p $DEST
	#clear the log file
	cat /dev/null > $LOG
	if [ ! -d /store ] && [ -d $DEST ]; then
	   echo "Sistem gerekli klasörleri /store ve $DEST bulamadi. Script sonlandiriliyor"
           exit 1
	fi
	clear
	title "Getting disk information"
	$LSBLK >> $LOG
	$DF -h >> $LOG
	title "Getting version information"
	/opt/qradar/bin/myver -v >>  $LOG
	title "Checking system information" 
	$DMI -t system| grep -e "Manufacturer" -e "Product Name" >> $LOG
	$DMI -t system | grep -A 1 -e "System Boot Information" >> $LOG
	title "Checking write speed"
	$DD if=/dev/zero of=/store/tempfile bs=1M count=1024 conv=sync 2>> $LOG
	title "Clearing caches"
	$SYSCTL -w vm.drop_caches=3 > /dev/null
	title "Checking read speed"
	$DD if=/store/tempfile of=/dev/null bs=1M count=1024 2>> $LOG
	rm -f /store/tempfile
	title "Checking CPU number" 
	$LSCPU | grep -e "^CPU(s):" | awk {'print "CPU adet:" $2'} >> $LOG
	title "Checking Load Average" 
	top -n1 -b  | awk -F, 'NR==1 {print $0}' >> $LOG
	title "Checking Load Average and Wait Time"
	counter=5
	while [ $counter -gt 0 ]; 
	do
	 top -n1 -b |awk -F, 'NR==3 {print "USER:"$1 " IDLE:"$4 " WA:"$5}' | sed 's/Cpu(s)://g' >> $LOG
	 echo "$counter"
	 sleep 10
	 counter=$(echo "$counter-1"|bc)
	done
	storevolume
	title "Checking IOSTAT stats" 
	counter=5
	echo "$getvolume store diski olarak tespit edildi"
	iostat -dmx $getvolume 1 1 >> $LOG
	while [ $counter -gt 0 ]; 
	do
	iostat -dmx  $getvolume 1 1 >> $LOG
	echo "$counter"
	sleep 10
        counter=$(echo "$counter-1"|bc)
	done
	title "Copying files"
	$CP /opt/qradar/conf/capabilities/hostcapabilities.xml ${DEST}/$(hostname)_hostcapabilities.xml
	$CP /opt/qradar/conf/deployment.xml ${DEST}/$(hostname)_deployment.xml
	title "Checking missing or mismatched tokens"
        title "Patch Status"
        /opt/qradar/support/all_servers.sh -X >> $LOG	
	title "Psql Jobs Started"
	title "Getting Managed Host Table"
	psql -U qradar << EOF
	\o | cat - >> $LOG
	SELECT id,ip,hostname,status,isconsole,appliancetype,primary_host,secondary_host FROM managedhost;
EOF
	title "Getting Server Host Table"
	psql -U qradar << EOF
	\o | cat - >> $LOG
	SELECT id,ip,hostname,status,managed_host_id,managementinterface FROM serverhost  where status != 14;
EOF
	title "Getting Deployed Component Table"
	psql -U qradar << EOF
	\o | cat - >> $LOG
	SELECT * FROM deployed_component;
EOF
	mybackupdate=$(date +"%d_%m_%Y" --date "1 days ago")
	title "Getting Backup Status"
	psql -U qradar << EOF
	\o | cat - >> $LOG
	select host_id,name,version,target_Date,type,status from backup where target_Date='$mybackupdate';
EOF

}



#TODO
#Ariel query ile arama yap, predicted disk failure ve disk doluluk ile ilgili. son 7 gün için
#JMX ile event average payload ve average record size'larını cikart

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
		exit 2
		;;
	esac
done
#REFERANS
#https://www.ibm.com/support/pages/node/6620291
#https://www.ibm.com/support/pages/qradar-how-monitor-and-check-if-cpu-bound-or-overloaded
#https://www.ibm.com/support/pages/qradar-troubleshooting-disk-io-performance-issues
#https://www.ibm.com/support/pages/node/6620291
#For virtual machines: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-kvm_guest_timing_management-steal_time_accounting#sect-KVM_guest_timing_management-Steal_time_accounting
#https://www.ibm.com/support/pages/qradar-deploy-times-out-due-missing-or-mismatched-tokens

