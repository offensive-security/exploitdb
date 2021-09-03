FLIR Systems FLIR Thermal Camera F/FC/PT/D Hard-Coded SSH Credentials


Vendor: FLIR Systems, Inc.
Product web page: http://www.flir.com
Affected version: Firmware version: 8.0.0.64
                  Software version: 10.0.2.43
                  Release: 1.4.1, 1.4, 1.3.4 GA, 1.3.3 GA and 1.3.2
                  FC-Series S (FC-334-NTSC)
                  FC-Series ID
                  FC-Series-R
                  PT-Series (PT-334 200562)
                  D-Series
                  F-Series

Summary: FLIR's PT-Series of high-performance, multi-sensor pan/tilt cameras
bring thermal and visible-light imaging together in a system that gives you
video and control over both IP and analog networks. The PT-Series' precision
pan/tilt mechanism gives you accurate pointing control while providing fully
programmable scan patterns, radar slew-to-cue, and slew-to-alarm functions.
PT-Series cameras define a new standard of performance with five models that
provide full 640x480 thermal resolution.

Desc: FLIR utilizes hard-coded credentials within its Linux distribution image.
These sets of credentials are never exposed to the end-user and cannot be changed
through any normal operation of the camera.

Tested on: Linux 2.6.18_pro500-davinci_evm-arm_v5t_le
           Linux 2.6.10_mvl401-davinci_evm-PSP_01_30_00_082
           Nexus Server/2.5.29.0
           Nexus Server/2.5.14.0
           Nexus Server/2.5.13.0
           lighttpd/1.4.28
           PHP/5.4.7


Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                            @zeroscience


Advisory ID: ZSL-2017-5436
Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5436.php


23.03.2017

--


root:indigo
root:video
default:video
default:[blank]
ftp:video