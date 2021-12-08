Device: Snap Server 410
OS: GuardianOS 5.1.041
Description: When logged in to CLI via ssh as admin (uid=1) you can escalate your privileges to uid 0 and get /bin/sh. In order to achieve this open 'less' which is available as default for viewing files (ie. less /tmp/top.log) and type in '!/bin/sh'. This will give you direct access to sh shell with UID 0. Tested only on OS version as above.