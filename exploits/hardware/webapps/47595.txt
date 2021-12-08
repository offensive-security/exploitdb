# Exploit Title: Smartwares HOME easy 1.0.9 - Client-Side Authentication Bypass
# Author: LiquidWorm
# Date: 2019-11-05
# Vendor: Smartwares
# Product web page: https://www.smartwares.eu
# Affected version: <=1.0.9
# Advisory ID: ZSL-2019-5540
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5540.php
# CVE: N/A

Summary: Home Easy/Smartwares are a range of products designed to remotely
control your home using wireless technology. Home Easy/Smartwares is very
simple to set up and allows you to operate your electrical equipment like
lighting, appliances, heating etc.

Desc: HOME easy suffers from information disclosure and client-side authentication
bypass vulnerability through IDOR by navigating to several administrative web pages.
This allowed disclosing an SQLite3 database file and location. Other functionalities
are also accessible by disabling JavaScript in your browser, bypassing the client-side
validation and redirection.

Tested on: Boa/0.94.13

/web-en/task.html
/web-en/action_task.html
/web-en/plan_task.html
/web-en/room.html
/web-en/room_set.html
/web-en/room_set2.html
/web-en/scene.html
/web-en/scene_set.html
/web-en/scene_set2.html
/web-en/system.html