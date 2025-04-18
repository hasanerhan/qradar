
#!/usr/bin/env bash
# AUTHOR      	: Hasan Erhan AYDINOGLU 
# EMAIL       	: hasan.erhan.aydinoglu@ibm.com
# DATE      	: 2023/05/24
# UPDATE    	:  
# VERSION     	: v.0.1
# DESCRIPTION 	: Bu script MegaCli64 binarry dosyasinin Backup Dizinine kopyalanarak yeni boş MegaCli64 dosyasinin 
#                 olusturumasi icin yazilmistir.
#                 
# CHANGELOG   	:
# TODO			: 
# VARIABLES 
SCRIPT=$(echo $0 | awk -F\/ '{print $NF}')
REV="0.1"
BKDZN="/store/IBMSupport"
SFILE="/opt/MegaRAID/MegaCli/MegaCli64"
FCRE=$(which touch)
MKDR=$(which mkdir)
CHMO=$(which chmod)

function version {
		clear
        echo -e "\tVERSION:$SCRIPT $REV"
        echo -e "\tAUTHOR : Hasan Erhan AYDINOGLU"
		echo -e "\tEMAIL  : hasan.erhan.aydinoglu@ibm.com"
		echo -e "\tDATE   : 2023/05/24"
		echo -e "\tDESC   : Bu script MegaCli64 binarry dosyasinin Backup Dizinine kopyalanarak yeni boş MegaCli64 dosyasinin olusturumasi icin yazilmistir."
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

function checkresult()

{

	if [ $? -eq 0 ]
		then
			echo "$1 islemi basarili bir sekilde tamamlandi"
			sleep 1
	else
			echo "$1 islemi basarisiz oldu. Cikis yapiliyor"
			exit 1
	fi
}

function runscript {
	#Dosya ve Dizin Kontrol
	clear
	if [ ! -f $SFILE ]
	then
		echo -e "$SFILE Dosyasi Bulunamadi\nBetik sonlandiriliyor"
		exit 1
	else
		echo -e "$SFILE bulundu betik devam ediyor..."
	fi
	if [ ! -d $BKDZN ]
	then
		echo -e "$BKDZN backup dizini bulunamadi, oluşturuluyor..."
	    $MKDR $BKDZN
		checkresult "Backup dizin olusturma"
	fi
	mv $SFILE $BKDZN
	checkresult "Orijinal dosya tasima"
	$FCRE $SFILE
	checkresult "Yeni dosya olusturma"
	echo -e "#!/bin/bash\nexit 0" > $SFILE
	checkresult "Dosya icerigi olusturma"
	$CHMO u+x $SFILE
	checkresult "Gerekli izinleri verme"
	$SFILE
	if [ $? -eq 0 ]
	then
		echo -e "Betik Basariyla Tamamlandi\nDosya icerigi asagidaki gibidir"
		echo "======== BASARILI ==============="
		cat $SFILE
	else
		echo -e "Betik de problem olustu\nDosya icerigi asagidaki gibidir"
		echo "=========== HATA ================"
		cat $SFILE
	fi
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
	exit 2
	;;
	esac
done