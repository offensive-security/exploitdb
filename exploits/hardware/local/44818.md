# PS4 5.05 Kernel Exploit
---
## Summary
In this project you will find a full implementation of the second "bpf" kernel exploit for the PlayStation 4 on 5.05. It will allow you to run arbitrary code as kernel, to allow jailbreaking and kernel-level modifications to the system. This exploit also contains autolaunching code for Mira and Vortex's HEN payload. Subsequent loads will launch the usual payload launcher.

This bug was discovered by qwertyoruiopz, and can be found hosted on his website [here](http://crack.bargains/505k/). The [GitHub Pages site](https://cryptogenic.github.io/PS4-5.05-Kernel-Exploit/) automatically generated from this repository should also work.

Download: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/44818.zip

## Patches Included
The following patches are made by default in the kernel ROP chain:
1) Disable kernel write protection
2) Allow RWX (read-write-execute) memory mapping
3) Syscall instruction allowed anywhere
4) Dynamic Resolving (`sys_dynlib_dlsym`) allowed from any process
4) Custom system call #11 (`kexec()`) to execute arbitrary code in kernel mode
5) Allow unprivileged users to call `setuid(0)` successfully. Works as a status check, doubles as a privilege escalation.

## Payloads included
1) Vortex's HEN (Homebrew Enabler)
2) Mira

## Notes
- The page will crash on successful kernel exploitation, this is normal


## Contributors
Massive credits to the following:

- [qwertyoruiopz](https://twitter.com/qwertyoruiopz)
- [Flatz](https://twitter.com/flat_z)
- [Vortex](https://github.com/xvortex)
- [OpenOrbis Team](https://github.com/OpenOrbis/)
- Anonymous