#!/bin/bash
# This script requires: nuclei, wafw00f, amass, chaos, dnsx, httpx,
# github-subdomains, aws-cli, hakip2host and tor must be running 
# on port 9050
#
# Copyright 2024 by 6mile/Paul McCarty.  All rights reserved.
#

banner() {
cat << "EOF"
Automated recon optimized for fast, efficient mass scanning

   -_____                ,,     /\\,/\\,
     ' | -,    _         ||    /| || ||    _
    /| |  |`  < \, ,._-_ ||/\  || || ||   < \,  _-_,  _-_,
    || |==||  /-||  ||   ||_<  ||=|= ||   /-|| ||_.  ||_.
   ~|| |  |, (( ||  ||   || | ~|| || ||  (( ||  ~ ||  ~ ||
    ~-____,   \/\\  \\,  \\,\  |, \\,\\,  \/\\ ,-_-  ,-_-
   (                          _-
						   by 6mile
-----------------------------------------------------------
EOF
}

# You should change these to suite your needs
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
GITHUBTOKEN=ghp_aaaaBBBBccccDDDDeeeeFFFFggggHHHHiiii
MASSDIR=/root/projects/darkmass
S3BUCKET=darkmass

if [[ -z $@ ]]; then
	banner;
	echo "You did not include any parameters. Use --help for options.";
        echo; exit 1;
fi

while [[ "$#" -gt 0 ]]; do
	    case $1 in
        -a|--amass) USEAMASS="1" ;;
        -c|--cloud) CLOUD="1" ;;
        -d|--domain) DOMAIN="$2"; shift ;;
        -f|--files) KEEPFILES="1" ;;
        -g|--headers) HEADERS="1" ;;
        -h|--help) SHOWHELP="1" ;;
        -i|--input) INPUT="$2"; shift ;;
        -ks|--kitchensink) KITCHENSINK="1" ;;
        -l|--silent) SILENT="1";exec > /dev/null ;;
		-as|--asnsubdomain) ASNSUBDOMAIN="1" ;;
        -n|--asn) ASN="1" ;;
        -p|--port) PORTSCAN="1" ;;
        -r|--report) REPORTING="1" ;;
        -s|--scan) DOSCAN="1" ;;
        -t|--tor) USETOR="1" ;;
        -w|--waf) FINDWAF="1" ;;
	-x|--examples) EXAMPLES="1" ;;
        *) banner; echo "Unknown parameter. Use --help for options."; exit 1 ;;
    esac
    shift
done

if [[ $SILENT != "1" ]]; then banner;fi

if [[ $SHOWHELP == "1" ]]; then
	echo "Welcome to the DarkMass help section. Here are the options:"
	echo "-----------------------------------------------------------"
	echo "-a|--amass        Use Amass to gather additional subdomains.  This will make the script MUCH slower."
	echo "-c|--cloud        Enumerate all AWS services."
	echo "-d|--domain       The domain to scan.  This should be a TLD like example.org."
	echo "-f|--files        Keep local files after recon completes."
	echo "-g|--headers      Check secuity headers for HSTS and CSP."
	echo "-h|--help         Show the help options."
        echo "-i|--input        Provide a list of hosts to use instead of running subdomain enumeration."
        echo "-ks|--kitchensink	Throw the kitchen sink at it. Use all available parameters except Tor."
        echo "-l|--silent       Silent mode.  ie., Don't send stdout to your terminal."
	echo "-as|--asnsubdomain	Gather additional subdomains by scanning entire IP range of companies ASN."
	echo "-n|--asn          Find the ASN or hosting information for all assets."
	echo "-p|--port         Port scan the assets using Naabu."
	echo "-r|--report       Send the output to the Elasticsearch reporting server."
	echo "-s|--scan         Scan the target with Nuclei."
	echo "-t|--tor          Proxy your outbound requess through the Tor network.  This will make your scans mostly anonymous AND slower."
	echo "-w|--waf          Identify what web application firewall (WAF) is being used, if any."
	echo "-x|--examples     See examples of how to use DarkMass."
	echo
	echo "Example: ./darkmass -s -d example.org -a -c -n -p -w -r"
	echo
	exit 0
	fi

if [[ $EXAMPLES == "1" ]]; then
	cat << "EOF"
FAST SUBDOMAIN ENUMERATION
This scan will quickly try to find subdomains for the supplied domain:
darkmass.sh -d tesla.com

SLOWER SUBDOMAIN ENUMERATION
This subdomain enumeration will find more assets but will take longer:
darkmass.sh -d tesla.com -a

FIND VULNERABILITIES USING NUCLEI
Adding the -s flag will enable Nulcei scanning.  By default Nuclei will look for critical, high, medium and low vulnerabilities.
darkmass.sh -d tesla.com -s

PORT SCAN ALL TARGETS
You can port scan all targets by adding the -p flag.
darkmass.sh -d tesla.com -p

PORT SCAN ALL TARGETS
You can port scan all targets by adding the -p flag.
darkmass.sh -d tesla.com -p

ENUMERATE ALL AWS SERVICES
Find all AWS services by adding the -c flag.
darkmass.sh -d tesla.com -c

IDENTIFY HOST INFORMATION VIA ASN
You can find
darkmass.sh -d tesla.com -c

EOF
exit 0
fi

if [[ -z $DOMAIN ]]; then echo "ERROR: Must include a DOMAIN to scan."; exit 1;fi
if [[ $USETOR == "1" ]] && [[ $REPORTING == "1" ]]; then echo "ERROR: You can't currently use Tor and reporting function at the same time.  This is a bug that the Nuclei team is working on"; exit 1; fi

if [[ $KITCHENSINK == "1" ]];then
	echo
	echo "==========================================================================================="
	echo "  KITCHEN SINK MODE"
	echo "  AMASS, AWS CLOUD, ASN, HSTS, CSP, PORTSCAN, FINDWAF and REPORTING are enabled!"
	echo "==========================================================================================="
	echo
	USEAMASS="1";
	CLOUD="1";
	KITCHENSINK="1";
	ASN="1";
	PORTSCAN="1";
	HEADERS="1";
	REPORTING="1";
	DOSCAN="1";
	FINDWAF="1";
	ASNSUBDOMAIN="1";
fi

# You probably shouldn't chnge these three globals
# Create the output directory here:
[ -d $MASSDIR/output/$DOMAIN ] || mkdir -p $MASSDIR/output/$DOMAIN
# Set the file naming standard here:
OUTFILE=$DOMAIN.$TIMESTAMP
# Set the output directory here:
OUT=$MASSDIR/output/$DOMAIN/$OUTFILE

# this section renames any exisiting files it finds
ADDEND=$RANDOM
#if [[ -s $DOMAIN.list ]]; then mv $DOMAIN.list $ADDEND.$DOMAIN.list;fi
#if [[ -s $DOMAIN.http ]]; then mv $DOMAIN.http $ADDEND.$DOMAIN.http;fi
#if [[ -s $DOMAIN.waf ]]; then mv $DOMAIN.waf $ADDEND.$DOMAIN.waf;fi
#if [[ -s $DOMAIN.hsts ]]; then mv $DOMAIN.hsts $ADDEND.$DOMAIN.hsts;fi
#if [[ -s $DOMAIN.csp ]]; then mv $DOMAIN.csp $ADDEND.$DOMAIN.csp;fi
#if [[ -s $DOMAIN.asn ]]; then mv $DOMAIN.asn $ADDEND.$DOMAIN.asn;fi
#if [[ -s $DOMAIN.aws ]]; then mv $DOMAIN.aws $ADDEND.$DOMAIN.aws;fi
#if [[ -s $DOMAIN.cloud ]]; then mv $DOMAIN.cloud $ADDEND.$DOMAIN.cloud;fi
#if [[ -s $DOMAIN.ports ]]; then mv $DOMAIN.ports $ADDEND.$DOMAIN.ports;fi
#if [[ -s $DOMAIN.nuclei.json ]]; then mv $DOMAIN.nuclei.json $ADDEND.$DOMAIN.nuclei.json;fi

if [[ -z $INPUT ]]; then
        LIST=$OUT.list
        #chaos -silent -d $DOMAIN >> $MASSDIR/$OUT.raw
        chaos -silent -d $DOMAIN >> $OUT.raw
        #subfinder -nW -silent -d $DOMAIN >> $MASSDIR/$OUT.raw
        subfinder -nW -silent -d $DOMAIN >> $OUT.raw
        #github-subdomains -raw -d $DOMAIN -t $GITHUBTOKEN >> $OUT.raw
        github-subdomains -raw -d $DOMAIN -t $GITHUBTOKEN -o $OUT.raw
        if [[ $USEAMASS == "1" ]]; then amass enum -d $DOMAIN >> $OUT.raw;fi

	if [[ $ASNSUBDOMAIN == "1" ]]; then
		ip_to_int() {
    		local ip="$1"
    		IFS=. read -r i1 i2 i3 i4 <<< "$ip"
    		echo "$(( (i1<<24) + (i2<<16) + (i3<<8) + i4 ))"
		}
		
		int_to_ip() {
		    local int="$1"
		    echo "$(( (int>>24)&255 )).$(( (int>>16)&255 )).$(( (int>>8)&255 )).$(( int&255 ))"
		}
			
		# Gets ASN data base 
		if [ ! -e "ip2asn-v4.tsv" ]; then
		    wget https://iptoasn.com/data/ip2asn-v4.tsv.gz 
		    gunzip ip2asn-v4.tsv.gz 
		fi

		COMPANY=$(echo $DOMAIN | awk -F "." '{print$1}')\

		ASN=$(python3 asnScraper.py $COMPANY  | grep -o 'AS[0-9]\+' | head -n1 | awk -F "S" '{print $2}')

		cat ip2asn-v4.tsv | grep -i "$ASN" | grep -i "$COMPANY" | awk -F " " '{print $1" "$2}' > $OUT.ipRange
			
		# Checks for asn in data and returns ip-range. Will prompt user to enter company name if no ranges found. 
			
		if [ -s $OUT.ipRange ] ; then
	    		while read line; do
		        	start_ip=$(echo $line | awk -F " " '{print $1}')
		        	end_ip=$(echo $line | awk -F " " '{print $2}')
		        	start_int=$(ip_to_int "$start_ip")
		        	end_int=$(ip_to_int "$end_ip")

			        for ((int = start_int; int <= end_int; int++)); do
			            current_ip=$(int_to_ip "$int")
			            echo "$current_ip" >> $OUT.ipList
		        	done
			done < $OUT.ipRange
		fi
		# Scans IP range for extra domainns
		cat $OUT.ipList | hakip2host | sort -u >> $OUT.tmp
		cat $OUT.tmp | awk -F " " '{print$3}' | sort -u | grep -v "*" >> $OUT.raw
		rm $OUT.tmp 
	fi
        cat $OUT.raw | sort -u | dnsx -silent >> $LIST
        cat $OUT.list | sort -u | httpx -silent >> $OUT.http
elif [[ -n $INPUT ]] && [[ $USEAMASS == "1" ]]; then
        echo "Can't enable subdomain enumeration when providing an INPUT file.  Exiting... "
        exit 1
elif [[ -n $INPUT ]] && [[ -f $INPUT ]]; then
        LIST=$INPUT;
        cat $LIST | sort -u | httpx -silent >> $OUT.http
	#echo $LIST >> $OUT.list
	cp $INPUT $OUT.list
fi

# Identify WAF
if [[ $FINDWAF = "1" ]] && [[ $USETOR != "1" ]]; then
	for wafurl in $(<$OUT.http); do wafw00f $wafurl -o - 2>/dev/null | sort -u | sed 's/^[ \t]*//' | sed 's/ \{1,\}/,/' >> $OUT.waf; done
elif [[ $FINDWAF = "1" ]] && [[ $USETOR == "1" ]]; then
	for wafurl in $(<$OUT.http); do wafw00f $wafurl -p socks5://localhost:9050 -o - 2>/dev/null | sort -u | sed 's/^[ \t]*//' | sed 's/ \{1,\}/,/' >> $OUT.waf; done
fi

# Tor scan
if [[ $USETOR == "1" ]] && [[ $DOSCAN = "1" ]]; then
        timeout 20m nuclei -silent -s critical,high,medium,low -etags intrusive,dos,router,modem,default-login,securestack-bad -p 'socks5://localhost:9050' -eid weak-cipher-suites,mismatched-ssl-certificate,self-signed-ssl,expired-ssl,mismatched-ssl-certificate,untrusted-root-certificate,http-missing-security-headers -l $OUT.http -j -o $OUT.nuclei.json -fr

# Exposed reporting scan
elif [[ $REPORTING == "1" ]] && [[ $DOSCAN = "1" ]]; then
        timeout 20m nuclei -silent -s critical,high,medium,low -etags intrusive,dos,router,modem,default-login,securestack-bad -eid weak-cipher-suites,mismatched-ssl-certificate,self-signed-ssl,expired-ssl,mismatched-ssl-certificate,untrusted-root-certificate,http-missing-security-headers -rc /etc/elasticsearch/nuclei-config.yaml -l $OUT.http -j -o $OUT.nuclei.json -fr

# Exposed scan
elif [[ $DOSCAN == "1" ]] && [[ $REPORTING != "1" ]]; then
        timeout 20m nuclei -silent -s critical,high,medium,low -etags intrusive,dos,router,modem,default-login,securestack-bad -eid weak-cipher-suites,mismatched-ssl-certificate,self-signed-ssl,expired-ssl,mismatched-ssl-certificate,untrusted-root-certificate,http-missing-security-headers -l $OUT.http -j -o $OUT.nuclei.json -fr
fi

# Portscan section
if [[ $PORTSCAN == "1" ]]; then
	naabu -silent -l $LIST -o $OUT.ports 1>/dev/null &
fi

# HEADERS HSTS & CSP section
if [[ $HEADERS == "1" ]]; then
	for sub in $(<$OUT.http); do
		timeout 10s curl -s -D- $sub -H 'user-agent: Chrome/51.0.2704.103 Safari/537.36' | grep -i "strict-transport-security:" >> $OUT.hsts;
		timeout 10s curl -s -D- $sub -H 'user-agent: Chrome/51.0.2704.103 Safari/537.36' | grep -i "content-security-policy:" >> $OUT.csp;
	done
fi

# ASN section
if [[ $ASN == "1" ]]; then
 	for asset in $(<$LIST); do
        	iplist=$(dig +short $asset | tail -1)
		ipoutput=$(curl -s "https://api.iplocation.net/?ip=$iplist" | jq -r '.isp')
		echo "$asset,$iplist,$ipoutput" >> $OUT.asn
	done
fi

# Cloud AWS service enumeration section - Cloud section
if [[ $CLOUD == "1" ]]; then
	nuclei -silent -tags aws -l $OUT.http -o $OUT.aws
	# AWS Count section
	AWSTOTAL=$(cat $OUT.aws | awk '{print $4}' | sort -u | wc -l)
fi
# Do stuff if there are some AWS services
if [[ $AWSTOTAL -gt 0 ]]; then
	echo "AWS-TOTAL-ASSETS=$AWSTOTAL" >> $OUT.cloud
	AWSSRVLIST=$(cat $OUT.aws | awk '{print $1}' | sed 's/[][]//g' | sed 's/aws-detect://' | sort -u)
	for service in $AWSSRVLIST; do
        	echo "Iterating through service list... $service";
        	svcnum=$(grep $service $OUT.aws | wc -l);
        	echo "$service=$svcnum" >> $OUT.cloud;
	done
fi

# Analytics section
echo
echo "##############################################" | tee -a $OUT.stats
echo "Statistics for $OUTFILE: " | tee -a $OUT.stats
echo "##############################################" | tee -a $OUT.stats
echo
totalassets=$(cat $LIST | sort -u | wc -l)
totalhttp=$(cat $OUT.http | sort -u | wc -l)
if [[ -s $OUT.waf ]]; then totalwaf=$(cat $OUT.waf | sort -u | wc -l);fi
if [[ -s $OUT.hsts ]]; then totalhsts=$(cat $OUT.hsts | sort -u | wc -l);fi
if [[ -s $OUT.csp ]]; then totalcsp=$(cat $OUT.csp | sort -u | wc -l);fi
if [[ -s $OUT.waf ]]; then nowaf=$(cat $OUT.waf | sort -u | grep '(None)' | wc -l);fi
if [[ -s $OUT.waf ]]; then identifiedwaf=$(cat $OUT.waf | sort -u | grep -v '(None)' | wc -l);fi
if [[ -s $OUT.waf ]]; then percentwaf=$(( $identifiedwaf*100/$totalhttp ));fi
if [[ -s $OUT.csp ]]; then csppercent=$(( $totalcsp*100/$totalhttp ));fi
if [[ -s $OUT.hsts ]]; then hstspercent=$(( $totalhsts*100/$totalhttp ));fi
echo "Total number of assets found              = $totalassets" | tee -a $OUT.stats
echo "Total number of web apps found            = $totalhttp" | tee -a $OUT.stats
echo "Number of apps with WAF disabled (BAD)    = $nowaf" | tee -a $OUT.stats
echo "Number of apps with WAF enabled  (GOOD)   = $identifiedwaf" | tee -a $OUT.stats
echo "Number of apps with CSP enabled  (GOOD)   = $totalcsp" | tee -a $OUT.stats
echo "Number of apps with HSTS enabled (GOOD)   = $totalhsts" | tee -a $OUT.stats
echo "Percentage of total web apps with WAF     = $percentwaf %" | tee -a $OUT.stats
echo "Percentage of total web apps with CSP     = $csppercent %" | tee -a $OUT.stats
echo "Percentage of total web apps with HSTS    = $hstspercent %" | tee -a $OUT.stats
echo "##############################################" | tee -a $OUT.stats
echo "$OUTFILE,$totalassets,$totalwaf,$nowaf,$identifiedwaf,$percentwaf" >> total-statistics.csv

# WAF analytics section
if [[ $FINDWAF = "1" ]]; then
        echo "WAF details for $OUTFILE: " | tee -a $OUT.stats
        echo "----------------------------------------------" | tee -a $OUT.stats
        WAFLIST=$(cat $OUT.waf | awk -F, '{print $2}' | awk '{print $1}' | sort -u)
        OLDIFS=$IFS
        IFS=$'\n'
        for wafprovider in $WAFLIST; do
                wafprovnum=$(grep $wafprovider $OUT.waf | wc -l);
                echo "$wafprovider=$wafprovnum" >> $OUT.wafvendors;
        done
        cat $OUT.wafvendors >> $OUT.stats

        IFS=$OLDIFS
        echo "##############################################" | tee -a $OUT.stats
fi

# ASN analytics section - Add ISP data to stats file
if [[ $ASN = "1" ]]; then
        echo "ASN details for $OUTFILE: " | tee -a $OUT.stats
        echo "----------------------------------------------" | tee -a $OUT.stats
        ASNLIST=$(cat $OUT.asn | awk -F, '{print $3}' | sed -r 's/\.$//' | sort -u)
        OLDIFS=$IFS
        IFS=$'\n'

        for asnprovider in $ASNLIST; do
                provnum=$(grep $asnprovider $OUT.asn | wc -l);
		percentageprov=$(( $provnum*100/$totalassets ))
                echo "$asnprovider=$provnum,percent=$percentageprov" >> $OUT.isp;
        done
        cat $OUT.isp >> $OUT.stats

        IFS=$OLDIFS
        echo "##############################################" | tee -a $OUT.stats
fi

# AWS analytics section - Add AWS data to stats file
if [[ $CLOUD = "1" ]]; then
        echo "AWS details for $OUTFILE: " | tee -a $OUT.stats
        echo "----------------------------------------------" | tee -a $OUT.stats
        cat $OUT.cloud >> $OUT.stats
        echo "##############################################" | tee -a $OUT.stats
fi

# Clean up section
if [[ -s $OUT.list ]] && [[ -z $INPUT ]]; then
        echo "Preparing to copy list files to S3...";
        aws s3 cp $OUT.list s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.list to S3" #&& rm $OUT.list;
elif [[ -n $INPUT ]]; then
        echo "Preparing to copy provided list file to S3...";
        aws s3 cp $LIST s3://$S3BUCKET/lists/$DOMAIN.$TIMESTAMP.list && echo "Successfully copied $LIST to S3"
        rm $LIST.$TIMESTAMP
fi
if [[ -s $OUT.http ]]; then
	echo "Preparing to copy http files to S3...";
	aws s3 cp $OUT.http s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.http to S3" #&& rm $OUT.http;
fi
if [[ -s $OUT.waf ]]; then
	echo "Preparing to copy WAF files to S3...";
	aws s3 cp $OUT.waf s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.waf to S3" #&& rm $OUT.waf;
fi
if [[ -s $OUT.asn ]]; then
	echo "Preparing to copy ASN files to S3...";
	aws s3 cp $OUT.asn s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.asn to S3" #&& rm $OUT.asn;
fi
if [[ -s $OUT.aws ]]; then
	echo "Preparing to copy AWS files to S3...";
	aws s3 cp $OUT.aws s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.aws to S3" #&& rm $OUT.aws;
fi
if [[ -s $OUT.ports ]]; then
	echo "Preparing to copy PORTS files to S3...";
	aws s3 cp $OUT.ports s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.ports to S3" #&& rm $OUT.ports;
fi
if [[ -s $OUT.hsts ]]; then
	echo "Preparing to copy HSTS files to S3...";
	aws s3 cp $OUT.hsts s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.hsts to S3" #&& rm $OUT.hsts;
fi
if [[ -s $OUT.csp ]]; then
	echo "Preparing to copy CSP files to S3...";
	aws s3 cp $OUT.csp s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.csp to S3" #&& rm $OUT.csp;
fi
if [[ -s $OUT.cloud ]]; then
	echo "Preparing to copy CLOUD files to S3...";
	aws s3 cp $OUT.cloud s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.cloud to S3" #&& rm $OUT.cloud;
fi
if [[ -s $OUT.stats ]]; then
	echo "Preparing to copy statistics files to S3...";
	aws s3 cp $OUT.stats s3://$S3BUCKET/lists/ && echo "Successfully copied $OUT.stats to S3" #&& rm $OUT.stats;
fi
if [[ -s $OUT.nuclei.json ]]; then
	echo "Preparing to copy Nuclei files to S3...";
        aws s3 cp $OUT.nuclei.json s3://$S3BUCKET/nuclei-output/ && echo "Successfully copied $OUT.nuclei.json to S3" #&& rm $OUT.nuclei.json;
elif [[ -f $OUT.nuclei.json ]]; then
	rm $OUT.nuclei.json;
fi
if [[ -f $OUT.txt ]]; then rm $OUT.txt; fi
if [[ -f $OUT.raw ]]; then rm $OUT.raw; fi
if [[ -f $OUT.ipRange ]]; then rm $OUT.ipRange; fi
if [[ -f $OUT.ipList ]]; then rm $OUT.ipList; fi

