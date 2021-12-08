source: https://www.securityfocus.com/bid/59/info

/etc/crash was installed setgid kmem and excutable by anyone. Any user can use the ! shell command escape to executes commands, which are then performed with group set to kmem.

$ /etc/crash
! sh