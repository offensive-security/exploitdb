# PS4 4.55 Kernel Exploit
---
## Summary
In this project you will find a full implementation of the "bpf" kernel exploit for the PlayStation 4 on 4.55. It will allow you to run arbitrary code as kernel, to allow jailbreaking and kernel-level modifications to the system. This release however, *does not* contain any code related to defeating anti-piracy mechanisms or running homebrew. This exploit does include a loader that listens for payloads on port `9020` and will execute them upon receival.

This bug was discovered by qwertyoruiopz, and can be found hosted on his website [here](http://crack.bargains/455/).

## Patches Included
The following patches are made by default in the kernel ROP chain:
1) Disable kernel write protection
2) Allow RWX (read-write-execute) memory mapping
3) Syscall instruction allowed anywhere
4) Dynamic Resolving (`sys_dynlib_dlsym`) allowed from any process
4) Custom system call #11 (`kexec()`) to execute arbitrary code in kernel mode
5) Allow unprivileged users to call `setuid(0)` successfully. Works as a status check, doubles as a privilege escalation.

## Notes
- Payloads from 4.05 should be fairly trivial to port unless they use hardcoded kernel offsets
- I've built in a patch so the kernel exploit will only run once on the system, you can make additional patches via payloads.
- A custom syscall is added (#11) to execute any RWX memory in kernel mode, this can be used to execute payloads that want to do fun things like jailbreaking and patching the kernel.


## Contributors
Massive credits to the following:

- [qwertyoruiopz](https://twitter.com/qwertyoruiopz)
- [Flatz](https://twitter.com/flat_z)
- Anonymous

Download: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/44196-v2.zip