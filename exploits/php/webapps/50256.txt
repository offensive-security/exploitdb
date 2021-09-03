# Exploit Title: WordPress Plugin Duplicate Page 4.4.1 - Stored Cross-Site Scripting (XSS)
# Date: 02/09/2021
# Exploit Author: Nikhil Kapoor
# Software Link: https://wordpress.org/plugins/duplicate-page/
# Version: 4.4.1
# Category: Web Application
# Tested on Windows

How to Reproduce this Vulnerability:

1. Install WordPress 5.7.2
2. Install and activate Duplicate Page
3. Navigate to Settings >> Duplicate Page and enter the XSS payload into the Duplicate Post Suffix input field.
4. Click Save Changes.
5. You will observe that the payload successfully got stored into the database and when you are triggering the same functionality at that time JavaScript payload is executing successfully and we are getting a pop-up.
6. Payload Used: "><svg/onload=confirm(/XSS/)>