#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# Automatically update your CloudFlare DNS record to the IP, Dynamic DNS
# Can retrieve cloudflare Domain id and list zone's, because, lazy

# Place at:
# curl https://raw.githubusercontent.com/yulewang/cloudflare-api-v4-ddns/master/cf-v4-ddns.sh > /usr/local/bin/cf-ddns.sh && chmod +x /usr/local/bin/cf-ddns.sh
# run `crontab -e` and add next line:
# */1 * * * * /usr/local/bin/cf-ddns.sh >/dev/null 2>&1
# or you need log:
# */1 * * * * /usr/local/bin/cf-ddns.sh >> /var/log/cf-ddns.log 2>&1
#
# Help: https://blog.natcloud.net/cf-ddns.html

# Usage:
# cf-ddns.sh -k cloudflare-api-key \
#            -u user@example.com \
#            -h host.example.com \     # fqdn of the record you want to update
#            -z example.com \          # will show you all zones if forgot, but you need this
#            -t A|AAAA                 # specify ipv4/ipv6, default: ipv4

# Optional flags:
#            -f false|true \           # force dns update, disregard local stored ip

# default config
SAVEPATH=

# API key, see https://www.cloudflare.com/a/account/my-account,
# incorrect api-key results in E_UNAUTH error
CFKEY=

# Username, eg: user@example.com
CFUSER=

# Zone name, eg: example.com
CFZONE_NAME=

# Hostname to update, eg: homeserver.example.com
CFRECORD_NAME=

# Record type, A(IPv4)|AAAA(IPv6), default IPv4
CFRECORD_TYPE=A

# Cloudflare TTL for record, between 120 and 86400 seconds
CFTTL=120

# Ignore local file, update ip anyway
FORCE=false

# Domain select list
DOMAIN_LIST=(1.demon.com 2.demon.com 3.demon.com)

# select_domain
selectDomain() {
	for element in ${DOMAIN_LIST[@]}; do
		ping -c 1 ${element} >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			DOMAIN=${element}
			return 0
		fi
	done
	return 1
}

# get_domain_ip
getDomainIp() {
	selectDomain
	if [ $? -eq 1 ]; then
		exit 3
	fi
	if [ "$CFRECORD_TYPE" = "A" ]; then
		PING=$(ping ${DOMAIN} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		echo $PING
	elif [ "$CFRECORD_TYPE" = "AAAA" ]; then
		PING=$(ping6 ${DOMAIN} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
		echo $PING
	else
		echo "$CFRECORD_TYPE specified is invalid, CFRECORD_TYPE can only be A(for IPv4)|AAAA(for IPv6)"
		exit 2
	fi
}

# get parameter
while getopts k:u:h:z:t:f: opts; do
	case ${opts} in
	k) CFKEY=${OPTARG} ;;
	u) CFUSER=${OPTARG} ;;
	h) CFRECORD_NAME=${OPTARG} ;;
	z) CFZONE_NAME=${OPTARG} ;;
	t) CFRECORD_TYPE=${OPTARG} ;;
	f) FORCE=${OPTARG} ;;
	esac
done

# If required settings are missing just exit
if [ "$CFKEY" = "" ]; then
	echo "Missing api-key, get at: https://www.cloudflare.com/a/account/my-account"
	echo "and save in ${0} or using the -k flag"
	exit 2
fi
if [ "$CFUSER" = "" ]; then
	echo "Missing username, probably your email-address"
	echo "and save in ${0} or using the -u flag"
	exit 2
fi
if [ "$CFRECORD_NAME" = "" ]; then
	echo "Missing hostname, what host do you want to update?"
	echo "save in ${0} or using the -h flag"
	exit 2
fi

# If the hostname is not a FQDN
if [ "$CFRECORD_NAME" != "$CFZONE_NAME" ] && ! [ -z "${CFRECORD_NAME##*$CFZONE_NAME}" ]; then
	CFRECORD_NAME="$CFRECORD_NAME.$CFZONE_NAME"
	echo " => Hostname is not a FQDN, assuming $CFRECORD_NAME"
fi

# Get current and old DOMAIN ip
DOMAIN_IP=$(getDomainIp)
DOMAIN_IP_FILE=$SAVEPATH/.cf-domain_ip_$CFRECORD_NAME.txt
if [ -f $DOMAIN_IP_FILE ]; then
	OLD_DOMAIN_IP=$(cat $DOMAIN_IP_FILE)
else
	echo "No file, need IP"
	OLD_DOMAIN_IP=""
fi

# If DOMAIN IP is unchanged an not -f flag, exit here
if [ "$DOMAIN_IP" = "$OLD_DOMAIN_IP" ] && [ "$FORCE" = false ]; then
	echo "DOMAIN IP Unchanged, to update anyway use flag -f true"
	exit 0
fi

# Get zone_identifier & record_identifier
ID_FILE=$SAVEPATH/.cf-id_$CFRECORD_NAME.txt
if [ -f $ID_FILE ] && [ $(wc -l $ID_FILE | cut -d " " -f 1) == 4 ] &&
	[ "$(sed -n '3,1p' "$ID_FILE")" == "$CFZONE_NAME" ] &&
	[ "$(sed -n '4,1p' "$ID_FILE")" == "$CFRECORD_NAME" ]; then
	CFZONE_ID=$(sed -n '1,1p' "$ID_FILE")
	CFRECORD_ID=$(sed -n '2,1p' "$ID_FILE")
else
	echo "Updating zone_identifier & record_identifier"
	CFZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$CFZONE_NAME" -H "X-Auth-Email: $CFUSER" -H "X-Auth-Key: $CFKEY" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)
	CFRECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records?name=$CFRECORD_NAME" -H "X-Auth-Email: $CFUSER" -H "X-Auth-Key: $CFKEY" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)
	echo "$CFZONE_ID" >$ID_FILE
	echo "$CFRECORD_ID" >>$ID_FILE
	echo "$CFZONE_NAME" >>$ID_FILE
	echo "$CFRECORD_NAME" >>$ID_FILE
fi

# If DOMAIN is changed, update cloudflare
echo "Updating DNS to $DOMAIN_IP"

RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID" \
	-H "X-Auth-Email: $CFUSER" \
	-H "X-Auth-Key: $CFKEY" \
	-H "Content-Type: application/json" \
	--data "{\"id\":\"$CFZONE_ID\",\"type\":\"$CFRECORD_TYPE\",\"name\":\"$CFRECORD_NAME\",\"content\":\"$DOMAIN_IP\", \"ttl\":$CFTTL}")

if [ "$RESPONSE" != "${RESPONSE%success*}" ] && [ "$(echo $RESPONSE | grep "\"success\":true")" != "" ]; then
	echo "Updated succesfuly!"
	echo $DOMAIN_IP >$DOMAIN_IP_FILE
	exit
else
	echo 'Something went wrong :('
	echo "Response: $RESPONSE"
	exit 1
fi
