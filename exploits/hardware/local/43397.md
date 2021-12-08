# PS4 4.05 Kernel Exploit
---
## Summary
In this project you will find a full implementation of the "namedobj" kernel exploit for the PlayStation 4 on 4.05. It will allow you to run arbitrary code as kernel, to allow jailbreaking and kernel-level modifications to the system. This release however, *does not* contain any code related to defeating anti-piracy mechanisms or running homebrew. This exploit does include a loader that listens for payloads on port `9020` and will execute them upon receival.

You can find fail0verflow's original write-up on the bug [here](https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/), you can find my technical write-up which dives more into implementation specifics ~~here~~ (this is still in progress and will be published within the next few days).

## Patches Included
The following patches are made by default in the kernel ROP chain:
1) Disable kernel write protection
2) Allow RWX (read-write-execute) memory mapping
3) Dynamic Resolving (`sys_dynlib_dlsym`) allowed from any process
4) Custom system call #11 (`kexec()`) to execute arbitrary code in kernel mode
5) Allow unprivileged users to call `setuid(0)` successfully. Works as a status check, doubles as a privilege escalation.

## Notes
- This exploit is actually incredibly stable at around 95% in my tests. WebKit very rarely crashes and the same is true with kernel.
- I've built in a patch so the kernel exploit will only run once on the system. You can still make additional patches via payloads.
- A custom syscall is added (#11) to execute any RWX memory in kernel mode, this can be used to execute payloads that want to do fun things like jailbreaking and patching the kernel.
- An SDK is not provided in this release, however a barebones one to get started with may be released at a later date.
- I've released a sample payload [here](http://www.mediafire.com/file/n4boybw0e06h892/debug_settings.bin) that will make the necessary patches to access the debug menu of the system via settings, jailbreaks, and escapes the sandbox.

## Contributors
I was not alone in this exploit's development, and would like to thank those who helped me along the way below.

- [qwertyoruiopz](https://twitter.com/qwertyoruiopz)
- [Flatz](https://twitter.com/flat_z)
- [CTurt](https://twitter.com/CTurtE)
- Anonymous


E-DB Note: Download ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/43397.zip