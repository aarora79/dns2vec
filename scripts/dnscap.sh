#!/bin/bash
# nohup'ing this works because it keeps the bash running
# doing the command directly (timeout + nohup) fails because as soon as the process quits, it kills the bash session

VIP4=`ip add show eth0 | grep "inet " | awk '{print $2}' | sed 's/\([0-9]\+.[0-9]\+.[0-9]\+.\)[0-9]\+\/.*/\1132/g'`
VIP6=`ip add show eth0 | grep "inet6 2001" | awk '{print $2}' | rev | cut -b 5- | rev | sed 's/\(.*\)/\121/g'`
while true; do
  timeout 84600 tcpdump -ttni eth0 "port 53 and (dst $VIP4 or dst $VIP6) and (src net 100.0.0.0/8 or src net 2001:5b0::/32)" | awk -F " " '{print     $1 "," $2 "," $3 "," $7 "," $8}' | egrep -v ",,$|SOA|1au" | sed 's/\?//g' | sed 's/.$//' | sed 's/\.[0-9]\+\,\([A|AAAA|TXT|CNAME|SRV]\)/,\1/g' | gzip > dns_queries.`date +%m%d`.gz
done
