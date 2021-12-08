full disclosure: http://seclists.org/fulldisclosure/2009/Dec/253

[ Sunbird 0.9 Array Overrun (code execution) ]

Author: Maksymilian Arciemowicz and sp3x
http://SecurityReason.com
Date:
- Dis.: 07.05.2009
- Pub.: 11.12.2009

CVE: CVE-2009-0689
CWE: CWE-199
Risk: High
Remote: Yes

Affected Software:
- Sunbird 0.9

NOTE: Prior versions may also be affected.

Original URL:
http://securityreason.com/achievement_securityalert/77


--- 0.Description ---
Mozilla Sunbird is a cross-platform calendar application, built upon
Mozilla Toolkit. Our goal is to provide you with a full-featured and
easy to use calendar application that you can use around the world.


--- 1. Sunbird 0.9 Remote Array Overrun (Arbitrary code execution) ---
The main problem exist in dtoa implementation. Sunbird has the same dtoa
as Firefox, etc. Problem exist in js3250.dll (version 4.0.0 - Netscape
32-bit JavaScript Module) DLL library

and it is the same like SREASONRES:20090625.

http://securityreason.com/achievement_securityalert/63

but fix for SREASONRES:20090625, used by openbsd was not good.
More information about fix for openbsd and similars SREASONRES:20091030,

http://securityreason.com/achievement_securityalert/69

We can create any number of float, which will overwrite the memory. In
Kmax has defined 15. Functions in dtoa, don't checks Kmax limit, and
it is possible to call 16>test.ics');
print myfile $header.$s.$expl.$footer;
-----------------------

0:000> r
eax=015e06f9 ebx=00000001 ecx=658cebec edx=00000002 esi=015e0710
edi=015e06f9
eip=600f154f esp=0012e330 ebp=0012e35c iopl=0 nv up ei pl nz na
pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
efl=00010206
js3250!JS_strtod+0xb0a:
600f154f 8b01 mov eax,dword ptr [ecx]
ds:0023:658cebec=????????
0:000> ub 600f1551
js3250!JS_strtod+0xaf2:
600f1537 83c414 add esp,14h
600f153a 8b75fc mov esi,dword ptr [ebp-4]
600f153d e96bf5ffff jmp js3250!JS_strtod+0x68 (600f0aad)
600f1542 56 push esi
600f1543 57 push edi
600f1544 8b7c240c mov edi,dword ptr [esp+0Ch]
600f1548 8d0cbd08d01460 lea ecx,js3250!js_XMLClass+0x560
(6014d008)[edi*4]
600f154f 8b01 mov eax,dword ptr [ecx]
0:000> !exchain
0012fc9c: USER32!_except_handler3+0 (7e39048f)
CRT scope 0, func: USER32!UserCallWinProc+10a (7e39ac2d)
0012fcf4: USER32!_except_handler3+0 (7e39048f)
CRT scope 0, filter: USER32!DispatchMessageWorker+113 (7e39074a)
func: USER32!DispatchMessageWorker+126 (7e390762)
0012fd5c: sunbird!jpeg_mem_term+eb7 (00849745)
0012ffb0: sunbird!jpeg_fdct_islow+266a4 (00848818)
0012ffe0: kernel32!_except_handler3+0 (7c839ac0)
CRT scope 0, filter: kernel32!BaseProcessStart+29 (7c843882)
func: kernel32!BaseProcessStart+3a (7c843898)
Invalid exception stack at ffffffff
0:000> k
ChildEBP RetAddr
WARNING: Stack unwind information not available. Following frames may be
wrong.
0012e35c 600f15f3 js3250!JS_strtod+0xb0a
0012e37c 600f0ef9 js3250!JS_strtod+0xbae
0012e3f4 6010e8eb js3250!JS_strtod+0x4b4
0012e448 6010e3c6 js3250!JSLL_MinInt+0x1dcf
0012e46c 60103fb5 js3250!JSLL_MinInt+0x18aa
0012e5dc 6010195e js3250!js_Invoke+0x2c1b
0012e694 60101cb2 js3250!js_Invoke+0x5c4
0012e71c 60101e0a js3250!js_Invoke+0x918
0012e74c 6011350d js3250!js_Invoke+0xa70
0012e7a4 600e3c41 js3250!js_FindProperty+0x974
0012e7bc 004274cf js3250!JS_SetProperty+0x36
0012e978 0042593e sunbird!NS_RegistryGetFactory+0x1c585
0012ea44 6035c7f1 sunbird!NS_RegistryGetFactory+0x1a9f4
0012ea60 6035d30b xpcom_core!nsXPTCStubBase::Stub3+0x20
0012ea74 00421fde xpcom_core!XPTC_InvokeByIndex+0x27
0012ec2c 0041fe00 sunbird!NS_RegistryGetFactory+0x17094
0012ecc0 60101906 sunbird!NS_RegistryGetFactory+0x14eb6
0012ed80 60101cb2 js3250!js_Invoke+0x56c
0012ee08 60101e0a js3250!js_Invoke+0x918
0012ee38 6011350d js3250!js_Invoke+0xa70


--- 3. SecurityReason Note ---
Officialy SREASONRES:20090625 has been detected in:
- OpenBSD
- NetBSD
- FreeBSD
- MacOSX
- Google Chrome
- Mozilla Firefox
- Mozilla Seamonkey
- Mozilla Thunderbird
- Mozilla Sunbird
- Mozilla Camino
- KDE (example: konqueror)
- Opera
- K-Meleon
- F-Lock

This list is not yet closed.


--- 4. Fix ---
NetBSD fix (optimal):
http://cvsweb.netbsd.org/bsdweb.cgi/src/lib/libc/gdtoa/gdtoaimp.h

OpenBSD fix:
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/sum.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtorx.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtord.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtorQ.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtof.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtodg.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtod.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/smisc.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/misc.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/hdtoa.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/gethex.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/gdtoa.h
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/dtoa.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/dmisc.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/stdio/vfprintf.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/arch/vax/gdtoa/strtof.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtorxL.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtorf.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtordd.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtopxL.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtopx.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtopf.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtopdd.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtopd.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtopQ.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtodnrp.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtodI.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoIxL.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoIx.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoIg.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoIf.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoIdd.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoId.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/strtoIQ.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/qnan.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g_xfmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g_xLfmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g_ffmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g_dfmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g_ddfmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g__fmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/g_Qfmt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/gdtoa/arithchk.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/stdlib/gcvt.c
http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/stdlib/ecvt.c


--- 5. Credits ---
Discovered by sp3x and Maksymilian Arciemowicz from SecurityReason.com.


--- 6. Greets ---
Infospec p_e_a pi3


--- 7. Contact ---
Email:
- cxib {a.t] securityreason [d0t} com
- sp3x {a.t] securityreason [d0t} com

GPG:
- http://securityreason.com/key/Arciemowicz.Maksymilian.gpg
- http://securityreason.com/key/sp3x.gpg

http://securityreason.com/
http://securityreason.pl/