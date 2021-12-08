PS4 4.0x Code Execution
==============
This repo is my edit of the [4.0x webkit exploit](http://rce.party/ps4/) released by [qwertyoruiopz](https://twitter.com/qwertyoruiopz). The edit re-organizes, comments, and adds portability across 3.50 - 4.07 (3.50, 3.55, 3.70, 4.00, and of course 4.06/4.07). The commenting and reorganization was mostly for my own learning experience, however hopefully others can find these comments helpful and build on them or even fix them if I've made mistakes. The exploit is much more stable than FireKaku and sets up the foundation for running basic ROP chains and returns to normal execution. Credit for the exploit goes completely to qwertyoruiopz.

Organization
==============
Files in order by name alphabetically;
* expl.js - Contains the heart of the exploit and establishes a read/write primitive.
* gadgets.js - Contains gadget maps and function stub maps for a variety of firmwares. Which map is used is determined in the post-exploitation phase.
* index.html - The main page for the exploit. Launches the exploit and contains post-exploitation stuff, as well as output and code execution.
* rop.js - Contains the ROP framework modified from Qwerty's original exploit as well as the array in which module base addresses are held and gadget addresses are calculated.
* syscalls.js - Contains a system call map for a variety of firmwares as well as a 'name -> number' map for syscall ID's.

Usage
==============
Simply setup a web-server on localhost using xampp or any other program and setup these files in a directory. You can then go to your computer's local IPv4 address (found by running ipconfig in cmd.exe) and access the exploit.

Notes
==============
* The exploit is pretty stable but will still sometimes crash. If the browser freezes simply back out and retry, if a segmentation fault (identified by prompt "You do not have enough free system memory") occurs, refresh the page before trying again as it seems to lead to better results.
* This only allows code execution in ring3, to get ring0 execution a kernel exploit and KROP chain is needed.
* If I've made an error (particularily having to do with firmware compatibility and gadgets) feel free to open an issue on the repo.
* The exploit has been tested on 3.55 and 4.00, it is assumed to work on other firmwares listed but not guaranteed, again if you encounter a problem - open an issue on the repo.

Credits
==============
qwertyoruiopz - The original exploit, the likes of which can be found [here](http://rce.party/ps4/).

Download: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/44198.zip