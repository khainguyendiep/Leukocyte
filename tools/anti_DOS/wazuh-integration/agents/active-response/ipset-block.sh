#!/bin/bash
# /var/ossec/active-response/bin/ipset-block.sh

LOCAL=$(dirname $0)
source $LOCAL/active-responses.sh

LOG_FILE="/var/ossec/logs/active-responses.log"
SET_NAME="antidos-block"
SET_TIMEOUT=600

# create ipset
if ! ipset list "$SET_NAME" &>/dev/null; then
    ipset create "$SET_NAME" hash:ip timeout "$SET_TIMEOUT"
fi

# ==== Whitelist of IPs/subnets do not allow to block ====
WHITELIST=(
  "127.0.0.1"
  "10.0.0.1"        # gateway
  "10.0.0.2"       # IP wazuh-manager
)

# write the moment of an IP is blocked or unblocked
log_msg() {
  (
    flock -x 200 # ensure 1 instance write log at a given moment in case many alert trigger at the same time
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
  ) 200>>"$LOG_FILE.lock"
}

INPUT_JSON=$(cat)

# clean field 'full_log' to avoid regex error
CLEANED_JSON=$(python3 -c "
import sys, json, re

raw = sys.stdin.read()
cleaned = re.sub(r',\"full_log\":\"\{.*?\}\"(?=,\"decoder\")', '', raw)
#				      ^ Non-greedy component.
print(cleaned)
			 " <<< "$INPUT_JSON" 2>> /tmp/ar_debug.log)

COMMAND=$(echo $CLEANED_JSON | jq -r '.command // empty')
echo "$CLEANED_JSON" >> /tmp/ar_debug.log
IP=$(echo $CLEANED_JSON | jq -r '.parameters.alert.data.network.src_ip // empty')

# ==== 1. Validate: COMMAND need to exist and valid ====
if [[ "$COMMAND" != "add" && "$COMMAND" != "delete" ]]; then
  log_msg "ERROR: Invalid or missing command '$COMMAND'. Aborting."
  exit 1
fi

# ==== 2. Validate: IP can not empty ====
if [[ -z "$IP" ]]; then
  log_msg "ERROR: src_ip field is empty or missing. Aborting."
  exit 1
fi

# ==== 3. Validate: right format (IPv4) ====
IP_REGEX='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if [[ ! "$IP" =~ $IP_REGEX ]]; then
  log_msg "ERROR: '$IP' is not a valid IPv4 address. Aborting."
  exit 1
fi

   # checking each octet need to valid in range of 0-255
valid_octets=true
IFS='.' read -r o1 o2 o3 o4 <<< "$IP"
for octet in "$o1" "$o2" "$o3" "$o4"; do
  if (( octet < 0 || octet > 255 )); then
    valid_octets=false
    break
  fi
done

if [[ "$valid_octets" == false ]]; then
  log_msg "ERROR: '$IP' has invalid octet range. Aborting."
  exit 1
fi

# ==== 4. check IP is private/reserved or not, avoid blocking wrong IP ====
if [[ "$IP" =~ ^127\. ]] || [[ "$IP" =~ ^0\. ]] || [[ "$IP" =~ ^169\.254\. ]]; then
  log_msg "WARNING: '$IP' is a reserved/loopback address, skipping block."
  exit 0
fi

# ==== 5. Whitelist check ====
is_whitelisted() {
  local ip_to_check="$1"
  local entry

  for entry in "${WHITELIST[@]}"; do
    if [[ "$entry" == *"/"* ]]; then
      # if entry is a CIDR subnet, then check by python
      if python3 -c "
import ipaddress, sys
ip = ipaddress.ip_address('$ip_to_check')
net = ipaddress.ip_network('$entry', strict=False)
sys.exit(0 if ip in net else 1)
	 	    " 2>/dev/null; then
	return 0
      fi
    else
      # not CIDR subnet, compare like 2 string
      if [[ "$ip_to_check" == "$entry" ]]; then
        return 0
      fi
    fi
  done
  return 1
}

if is_whitelisted "$IP"; then
  log_msg "SKIP: '$IP' is in whitelist, not blocking."
  exit 0
fi

# ==== 6. ensure ipset is exist, if it doesn't, create new ====
#after 600s remove the ip from ipset
ipset list "$SET_NAME" &>/dev/null || ipset create "$SET_NAME" hash:ip timeout "$SET_TIMEOUT"

# ==== 7. Write log
case $COMMAND in
  add)
    if ipset add "$SET_NAME" "$IP" timeout "$SET_TIMEOUT" -exist; then
      log_msg "ADD $IP SUCCESSFUL"
    else
      log_msg "ADD $IP FAILED"
      exit 1
    fi
  ;;
  delete)
    if ipset del "$SET_NAME" "$IP" -exist; then
      log_msg "DELETE $IP SUCCESSFUL"
    else
      log_msg "DELETE $IP FAILED"
      exit 1
    fi
  ;;
esac

exit 0
